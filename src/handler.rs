//! The module itself — what it holds between calls, and what each call does.

use crate::*;

#[derive(Default)]
pub(crate) struct Loki {
    /// The last scan's report, kept for the tab it is shown in.
    pub(crate) report: Option<Report>,
    /// Scan settings, loaded from `tools/settings.json` on first use and kept
    /// here so a scan does not have to re-read them off the disk.
    settings: Option<Value>,
    /// What this tab is set to scan. Decides most of the screen, because the
    /// three take different inputs and share almost no settings.
    mode: Mode,
    /// The autostart entries the last autoruns scan was built from, kept so its
    /// findings can name the key rather than the scratch file Loki read.
    staged: Vec<Staged>,
    /// Whether the scan screen is showing what the scanner has said.
    show_output: bool,
    /// Stop was pressed on an elevated scan that could not be stopped.
    still_running: bool,
    /// Stop was pressed. Carried to the report so the outcome reads as a scan
    /// that was ended rather than one that broke.
    stopped: bool,
    /// The last scan ran without privileges because this machine has no way to
    /// ask for them — the results have to say so.
    unelevated: bool,
    /// Whether this scan has already said it started.
    ///
    /// The corner notice is an *event*, but the running screen redraws several
    /// times a second and an elevated scan only becomes "running" during a poll
    /// — so without this the same alert would be raised on every poll for as
    /// long as the scan lasted.
    pub(crate) announced: bool,
    /// An elevation the host is running for us: the authorization prompt is on
    /// screen, or the elevated scan is under way. Polled rather than waited on,
    /// so the module keeps drawing while the user answers.
    elevation: Option<(u64, PathBuf)>,
    /// The running scan, if any. A scan takes minutes to hours, so it runs on
    /// its own thread and the view polls it — the module never blocks.
    job: Option<Job>,
}

impl Handler for Loki {
    fn capabilities(&self) -> Vec<String> {
        vec!["scan.ioc".into()]
    }

    fn invoke(
        &mut self,
        _capability: &str,
        method: &str,
        params: Value,
        host: &Host,
    ) -> Result<Value, RpcError> {
        // One lookup per call, then every view renders in that language.
        let lang = host.locale();
        let lang = lang.as_str();
        let t = |k: &str| catalog().tr(lang, k);

        match method {
            // The entry point decides which screen you get: no scanner ->
            // install it, scanner present -> the scan screen.
            "ui" => {
                self.report = None;
                Ok(if loki_bin(host).is_some() {
                    self.screen(host, lang, None)
                } else {
                    install_view(lang, None)
                })
            }
            "install" => Ok(installing_view(lang, 0)),
            // Perform one step, then hand the next to the view. A failure ends
            // the chain on the install screen carrying the reason, rather than
            // leaving the steps spinning forever.
            "i_step" => {
                let step = params.get("step").and_then(Value::as_u64).unwrap_or(0) as usize;
                match run_install_step(host, lang, step) {
                    Ok(()) => Ok(installing_view(lang, step + 1)),
                    Err(why) => Ok(install_view(lang, Some(&why))),
                }
            }
            // Open the settings pop-up over the scan screen.
            // Which scan is showing decides which settings are worth offering.
            "mode" => {
                self.mode = Mode::from_str(
                    params
                        .get("mode")
                        .and_then(Value::as_str)
                        .unwrap_or("files"),
                );
                self.report = None;
                Ok(self.screen(host, lang, None))
            }
            "config" => {
                let mode = self.mode;
                Ok(settings_modal(lang, self.cfg(host), mode))
            }
            // Save what the pop-up sent and return to the scan screen. The reply
            // is an ordinary view, which closes the pop-up over it.
            "config_save" => {
                let mut cfg = self.cfg(host).clone();
                if let Some(map) = cfg.as_object_mut() {
                    // Only keys we know: the form also carries the scan target
                    // and the signature fields, which are not settings.
                    for k in default_settings()
                        .as_object()
                        .map(|m| m.keys().cloned().collect::<Vec<_>>())
                        .unwrap_or_default()
                    {
                        // A checkbox arrives as a bool, the rest as strings.
                        if let Some(v) = params.get(&k) {
                            let keep = match map.get(&k) {
                                Some(Value::Bool(_)) => Value::Bool(v.as_bool().unwrap_or(false)),
                                _ => Value::String(
                                    v.as_str()
                                        .map(str::to_string)
                                        .unwrap_or_else(|| v.to_string()),
                                ),
                            };
                            map.insert(k, keep);
                        } else if matches!(map.get(&k), Some(Value::Bool(_))) {
                            // An unticked checkbox may simply not be sent, and
                            // an absent one must read as off rather than as
                            // "leave it alone" — otherwise it could never be
                            // turned off.
                            map.insert(k, Value::Bool(false));
                        }
                    }
                }
                save_settings(host, &cfg);
                self.settings = Some(cfg);
                Ok(self.screen(host, lang, None))
            }
            // The signature pop-up, raised from the settings one.
            "signatures" => Ok(signatures_modal(
                lang,
                &list_custom(host),
                bundled_rules(host),
                None,
            )),
            "sig_add" => {
                let src = params
                    .get("sig_file")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .trim()
                    .to_string();
                let kind = params
                    .get("sig_kind")
                    .and_then(Value::as_str)
                    .unwrap_or("yara")
                    .to_string();
                let err = if src.is_empty() {
                    Some(t("sig.no_file"))
                } else {
                    add_custom(host, &kind, &src)
                        .err()
                        .map(|e| t("sig.add_failed").replace("{error}", &e))
                };
                // Same pop-up id, so this redraws in place rather than opening
                // another over it.
                Ok(signatures_modal(
                    lang,
                    &list_custom(host),
                    bundled_rules(host),
                    err.as_deref(),
                ))
            }
            // The picker's current value rides along in the form, so the help
            // explains whatever kind is selected.
            "sig_help" => Ok(signature_help_modal(
                lang,
                params
                    .get("sig_kind")
                    .and_then(Value::as_str)
                    .unwrap_or("yara"),
            )),
            // Fetch (or refresh) the bundled YARA-Forge set. The pop-up shows a
            // spinner and invokes the work itself, so the download does not look
            // like a frozen screen.
            // Hand the file to the desktop's editor. Returns nothing: the
            // pop-up should stay exactly as it was, with the list still open
            // behind the editor that just launched.
            "sig_open" => {
                if let Some(p) = params
                    .get("id")
                    .and_then(Value::as_str)
                    .and_then(|id| signature_path(host, id))
                {
                    host.open("edit", &p.to_string_lossy());
                }
                Ok(Value::Null)
            }
            // Double-click, or "Open info" from the row menu.
            "sig_info" => {
                let id = params.get("id").and_then(Value::as_str).unwrap_or_default();
                let in_tab = params
                    .get("in_tab")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                Ok(signature_info_modal(lang, signature_info(host, id), in_tab))
            }
            "sig_core" => Ok(core_updating_modal(lang)),
            "sig_core_run" => {
                let err = update_bundled_rules(host)
                    .err()
                    .map(|e| t("sig.core_failed").replace("{error}", &e));
                Ok(signatures_modal(
                    lang,
                    &list_custom(host),
                    bundled_rules(host),
                    err.as_deref(),
                ))
            }
            "sig_remove" => {
                match params.get("id").and_then(Value::as_str) {
                    // The bundled set is a file like any other; deleting it
                    // leaves the scan with only what the user added, and the
                    // button beside Add turns back into Install.
                    Some("bundled") => {
                        if let Some(root) = install_root(host) {
                            let _ = std::fs::remove_file(
                                root.join("signatures")
                                    .join("yara")
                                    .join("yara-rules-core.yar"),
                            );
                        }
                    }
                    Some(id) => {
                        if let Some((kind, name)) = id.split_once('/') {
                            remove_custom(host, kind, name);
                        }
                    }
                    None => {}
                }
                Ok(signatures_modal(
                    lang,
                    &list_custom(host),
                    bundled_rules(host),
                    None,
                ))
            }
            // Start the scanner and hand the screen to the poller.
            "scan" => {
                // Only a file scan has a target the user chose; the other two
                // are this machine.
                let target = if self.mode != Mode::Files {
                    String::new()
                } else {
                    let chosen = params
                        .get("target")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .trim()
                        .to_string();
                    if chosen.is_empty() {
                        let msg = t("scan.no_target");
                        return Ok(self.screen(host, lang, Some(&msg)));
                    }
                    // The one place the scanner will not go however it is asked.
                    // Said now, because the alternative is a scan that reads
                    // nothing and reports the folder clean.
                    if is_cloud(&chosen) {
                        let msg = t("scan.cloud_target");
                        return Ok(self.screen(host, lang, Some(&msg)));
                    }
                    chosen
                };
                let Some(bin) = loki_bin(host) else {
                    return Ok(install_view(lang, Some(&t("scan.not_installed"))));
                };
                let Some(root) = install_root(host) else {
                    return Ok(self.screen(host, lang, Some(&t("install.no_dir"))));
                };
                // Put the user's own rules and indicators where the scanner
                // looks, every time — a reinstall replaces that directory.
                sync_signatures(host);

                let dir = root.parent().unwrap_or(&root).join(".scan");
                let _ = std::fs::create_dir_all(&dir);
                let cfg = self.cfg(host).clone();

                // An autostart scan asks the autoruns module what starts on this
                // machine, then lays each entry out as files the scanner can
                // read — the command as text for the string rules, and the
                // program it runs for the rest.
                let folder = if self.mode == Mode::Autoruns {
                    let enabled_only = cfg
                        .get("autoruns_enabled_only")
                        .and_then(Value::as_bool)
                        .unwrap_or(true);
                    let (entries, total) = match autorun_entries(host, enabled_only) {
                        Ok(v) => v,
                        Err(e) => {
                            let msg = t("scan.autoruns_failed").replace("{error}", &e);
                            return Ok(self.screen(host, lang, Some(&msg)));
                        }
                    };
                    let staged = stage_autoruns(&dir.join("autoruns"), &entries);
                    if staged.is_empty() {
                        let msg = t("scan.autoruns_none").replace("{n}", &total.to_string());
                        return Ok(self.screen(host, lang, Some(&msg)));
                    }
                    self.staged = staged;
                    Some(dir.join("autoruns").to_string_lossy().into_owned())
                } else {
                    (self.mode == Mode::Files).then_some(target)
                };

                // Every scan asks for privileges, not just the process one: a
                // scan of anything the user cannot read is skipped in silence —
                // no count, no warning, and a verdict that looks thorough.
                //
                // Required for processes, because Loki reads nothing at all
                // without them. Preferred for the rest: a machine with no way to
                // ask still scans what it can, and the results say so.
                self.unelevated = false;
                self.announced = false;
                if is_elevated() != Some(true) {
                    let (can, _how) = host.can_elevate();
                    if can {
                        let out = dir.join("report.jsonl");
                        let _ = std::fs::remove_file(&out);
                        let args = scan_args(&cfg, folder.as_deref(), &out);
                        let mut argv: Vec<&str> = vec![bin.to_str().unwrap_or_default()];
                        argv.extend(args.iter().map(String::as_str));
                        let workdir = bin.parent().unwrap_or(&root).to_string_lossy().into_owned();
                        if let Some(id) = host.elevate_async(&argv, Some(&workdir)) {
                            self.elevation = Some((id, out));
                            return Ok(authorizing_modal(lang));
                        }
                    }
                    if self.mode == Mode::Procs {
                        // Nothing to fall back to: process memory is unreadable
                        // without privileges, so this scan is over before it
                        // began — and that is an alert, not a quiet screen.
                        let view = self.screen(host, lang, Some(&t("scan.no_elevation")));
                        return Ok(notice(view, "error", t("notice.no_elevation")));
                    }
                    // Carry on unprivileged, and remember to say so.
                    self.unelevated = true;
                }

                host.log(&format!(
                    "[loki] scan {} in {}: {}",
                    self.mode.as_str(),
                    bin.parent().unwrap_or(&root).display(),
                    scan_args(&cfg, folder.as_deref(), &dir.join("report.jsonl")).join(" ")
                ));

                // Running the scanner and waiting on it happen on the worker's
                // thread, not this one.
                self.job = Some(Job::spawn(
                    bin.clone(),
                    // Signatures are resolved relative to the scanner, so it runs
                    // from its own directory.
                    bin.parent().unwrap_or(&root).to_path_buf(),
                    dir,
                    folder,
                    cfg.clone(),
                ));
                let view = scanning_view(lang, 0, 0, false, None);
                Ok(self.started_notice(lang, view))
            }
            // Show or hide what the scanner has said. The view keeps its own
            // polling, so the scan carries on either way.
            "toggle_output" => {
                self.show_output = !self.show_output;
                let outs = match &self.job {
                    Some(job) => job.outs.lock().unwrap().clone(),
                    None => self
                        .elevation
                        .as_ref()
                        .map(|(_, o)| vec![o.clone()])
                        .unwrap_or_default(),
                };
                let (lines, hits) = scan_progress(&outs);
                let shown = self.output_lines(&outs);
                Ok(scanning_view(lang, lines, hits, false, shown.as_deref()))
            }
            // Still going, or finished and ready to read.
            "s_poll" => {
                // An elevated scan is run by the host, not by our own worker, so
                // it is polled here rather than through `Job`.
                if let Some((id, out)) = self.elevation.clone() {
                    // The host says which it is. The scanner's own output is a
                    // poor stand-in: it can lag the prompt by seconds, which
                    // leaves "waiting for authorization" on screen long after
                    // the user gave it.
                    let done = match host.elevate_state(id) {
                        limen_sdk_rust::ElevateState::Authorizing => {
                            return Ok(authorizing_modal(lang))
                        }
                        limen_sdk_rust::ElevateState::Running => {
                            let (lines, hits) = scan_progress(std::slice::from_ref(&out));
                            let out = self.output_lines(std::slice::from_ref(&out));
                            // The authorization is where an elevated scan really
                            // begins, and it is answered here rather than at the
                            // press of Scan — so this is where it is announced.
                            let view = scanning_view(lang, lines, hits, false, out.as_deref());
                            return Ok(self.started_notice(lang, view));
                        }
                        limen_sdk_rust::ElevateState::Done(d) => d,
                    };
                    self.elevation = None;
                    if !done.ran {
                        let (why, alert) = auth_keys(&done);
                        let msg = t(why).replace("{error}", &done.message);
                        let view = self.screen(host, lang, Some(&msg));
                        return Ok(notice(view, "error", t(alert)));
                    }
                    return Ok(self.finish_paths(host, lang, &[out]));
                }

                // Everything is read off the job first so the borrow ends before
                // the job is cleared or consumed.
                let (err, running, outs, stopping) = match &self.job {
                    Some(job) => (
                        job.error.lock().unwrap().clone(),
                        !job.finished(),
                        job.outs.lock().unwrap().clone(),
                        job.stopping(),
                    ),
                    None => return Ok(self.screen(host, lang, None)),
                };
                if let Some(e) = err {
                    self.job = None;
                    return Ok(self.screen(
                        host,
                        lang,
                        Some(&t("scan.failed").replace("{error}", &e)),
                    ));
                }
                if running {
                    let (lines, hits) = scan_progress(&outs);
                    let shown = self.output_lines(&outs);
                    return Ok(scanning_view(lang, lines, hits, stopping, shown.as_deref()));
                }
                Ok(self.finish(host, lang))
            }
            // Stop a scan the user no longer wants.
            //
            // The worker notices between files, so this asks rather than waits —
            // blocking here would freeze the UI for as long as the scanner took
            // to die. Whatever was written by then is still a readable report,
            // and the next poll shows it.
            "stop" => {
                // An elevated scan is not ours to kill: it runs as root, and the
                // kernel will not let an unprivileged process signal it. The host
                // has a supervisor that can, and telling it so is the whole of
                // stopping — it is never a question for the user, who has already
                // answered it by pressing Stop.
                //
                // Whatever the scan wrote by then is a readable report, so show
                // that; and if there was nothing to ask, say it is still going
                // rather than leave a screen implying it stopped.
                self.stopped = true;
                if let Some((id, out)) = self.elevation.clone() {
                    let asked = host.elevate_stop(id);
                    self.elevation = None;
                    if !asked {
                        self.still_running = true;
                        host.log("[loki] stop asked for, but the scan is still running");
                    }
                    return Ok(self.finish_paths(host, lang, &[out]));
                }
                match &self.job {
                    Some(job) => job.stop(),
                    None => return Ok(self.screen(host, lang, None)),
                }
                Ok(scanning_view(lang, 0, 0, true, None))
            }
            // The last scan's report, in a tab of its own — opened by the scan
            // that produced it, and again from the screen when that tab is
            // gone.
            "report_tab" => Ok(match &self.report {
                Some(r) => results_view(lang, r, &wanted_levels(&Value::Null), 0),
                None => self.screen(host, lang, None),
            }),
            "filter" => {
                let Some(r) = &self.report else {
                    return Ok(self.screen(host, lang, None));
                };
                let page = params.get("page").and_then(Value::as_u64).unwrap_or(0) as usize;
                Ok(results_view(lang, r, &wanted_levels(&params), page))
            }
            "detail" => {
                let Some(r) = &self.report else {
                    return Ok(self.screen(host, lang, None));
                };
                let levels = wanted_levels(&params);
                let shown: Vec<&Event> = r
                    .findings
                    .iter()
                    .filter(|e| levels.iter().any(|l| l == &e.level))
                    .collect();
                let idx = params
                    .get("id")
                    .and_then(Value::as_str)
                    .and_then(|s| s.parse::<usize>().ok())
                    .unwrap_or(usize::MAX);
                match shown.get(idx) {
                    Some(e) => Ok(detail_view(lang, e)),
                    None => Ok(results_view(lang, r, &levels, 0)),
                }
            }
            "about" => Ok(json!({
                "name": "loki",
                "summary": "Runs Loki-RS (YARA + IOC) and reads its reports.",
                "methods": ["ui", "config", "signatures", "scan", "filter", "detail"],
            })),
            other => Err(RpcError::new(
                rpc::METHOD_NOT_FOUND,
                format!("no method {other}"),
            )),
        }
    }
}

impl Loki {
    /// Put the scanner's own words on the console.
    ///
    /// A scan that fails does so inside a child process nobody is watching, and
    /// Loki exits 0 either way — so the report is the only account of it, and
    /// the console is where it belongs when the scan is over.
    fn log_outcome(&self, host: &Host, r: &Report, outs: &[PathBuf]) {
        if r.stats.is_some() {
            return;
        }
        host.log("[loki] the scan wrote no summary — it did not finish:");
        for l in scan_output(outs, 12) {
            host.log(&format!("[loki]   {l}"));
        }
    }

    /// The scanner's output, when the user has asked to see it.
    ///
    /// Capped: this is redrawn on every poll, and a scan that runs for an hour
    /// would otherwise turn the screen into a wall nobody reads.
    fn output_lines(&self, outs: &[PathBuf]) -> Option<Vec<String>> {
        self.show_output.then(|| scan_output(outs, 40))
    }

    /// Settings, loaded from disk the first time they are wanted.
    pub(crate) fn cfg(&mut self, host: &Host) -> &Value {
        self.settings.get_or_insert_with(|| load_settings(host))
    }

    /// The scan screen, with the current settings summarised on it.
    pub(crate) fn screen(&mut self, host: &Host, lang: &str, err: Option<&str>) -> Value {
        let custom = list_custom(host).len();
        let mode = self.mode;
        // Offered only when something in this session actually provides it.
        let has_autoruns = host.has_capability(AUTORUNS_CAP);
        let has_report = self.report.is_some();
        main_view(lang, self.cfg(host), custom, mode, has_autoruns, has_report, err)
    }

    /// Say a scan has begun — once per scan.
    ///
    /// A scan runs for minutes to hours with nothing but a progress line to show
    /// for it, and an elevated one starts behind a password prompt the user may
    /// have answered and looked away from. So the start is worth an alert of its
    /// own, the same way the end is.
    pub(crate) fn started_notice(&mut self, lang: &str, view: Value) -> Value {
        if std::mem::replace(&mut self.announced, true) {
            return view;
        }
        notice(view, "ok", catalog().tr(lang, "notice.started"))
    }

    /// What a finished scan amounts to, in the corner: found something, found
    /// nothing, or never got far enough to say.
    pub(crate) fn scan_notice(&self, lang: &str, r: &Report, view: Value) -> Value {
        let t = |k: &str| catalog().tr(lang, k);
        // Keyed by Loki's own spelling of the level, which is upper case. Asking
        // for "alert" found nothing, every time, so every scan came back "ok" —
        // a green notice on a machine with a YARA match on it.
        let alerts = r.counts.get("ALERT").copied().unwrap_or(0);
        let warnings = ["WARNING", "ERROR"]
            .iter()
            .filter_map(|l| r.counts.get(*l))
            .sum::<usize>();
        // Stopped on purpose and with nothing to report: that is neither a
        // failure nor a clean bill, and calling it either would be wrong. What
        // was found before it stopped still counts, so that falls through.
        if r.stopped && alerts == 0 && warnings == 0 {
            return notice(view, "info", t("notice.stopped"));
        }
        if r.stats.is_none() && !r.stopped {
            // No summary means it did not finish, which is not a clean result.
            return notice(view, "error", t("notice.unfinished"));
        }
        if alerts > 0 {
            notice(
                view,
                "error",
                t("notice.alerts").replace("{n}", &alerts.to_string()),
            )
        } else if warnings > 0 {
            notice(
                view,
                "warning",
                t("notice.warnings").replace("{n}", &warnings.to_string()),
            )
        } else if r.stats.as_ref().is_some_and(|s| s.files == 0 && s.procs == 0) {
            // A scan that read nothing is not a clean scan. The scanner walks
            // away from whole classes of path in silence, and a folder it
            // refused ends exactly like an empty one — so the count is the
            // difference between "nothing wrong here" and "nothing was looked
            // at", and the green notice was claiming the first for both.
            notice(view, "warning", t("notice.nothing_read"))
        } else {
            notice(view, "ok", t("notice.clean"))
        }
    }

    /// The scan is over: keep the report, and hand it to a tab of its own.
    ///
    /// The screen that ran the scan goes back to being the screen you scan
    /// from — a report is something to read alongside the next scan, not
    /// something to have to leave in order to start one. The handover is an
    /// `auto` on this answer, so it happens once, when this screen arrives:
    /// `ui` returns the same screen without it, and coming back to this tab
    /// later does not open a second copy of the same report.
    pub(crate) fn present(&mut self, lang: &str, screen: Value, r: Report) -> Value {
        let screen = self.scan_notice(lang, &r, screen);
        self.report = Some(r);
        auto_in_tab(screen, "scan.ioc", "report_tab", json!({}))
    }

    /// Read a report the host ran on our behalf, with no `Job` behind it.
    fn finish_paths(&mut self, host: &Host, lang: &str, outs: &[PathBuf]) -> Value {
        let text = outs
            .iter()
            .filter_map(|p| std::fs::read_to_string(p).ok())
            .collect::<Vec<_>>()
            .join("\n");
        let mut r = parse(&text);
        r.unelevated = self.unelevated;
        r.still_running = std::mem::take(&mut self.still_running);
        r.stopped = std::mem::take(&mut self.stopped);
        if r.stats.is_none() {
            r.tail = scan_output(outs, 12);
        }
        self.log_outcome(host, &r, outs);
        let screen = self.screen(host, lang, None);
        self.present(lang, screen, r)
    }

    /// Read the report a finished (or stopped) scan left behind.
    pub(crate) fn finish(&mut self, host: &Host, lang: &str) -> Value {
        let Some(job) = self.job.take() else {
            return window(catalog().tr(lang, "title"), vec![]);
        };
        let outs = job.outs.lock().unwrap().clone();
        let text = outs
            .iter()
            .filter_map(|p| std::fs::read_to_string(p).ok())
            .collect::<Vec<_>>()
            .join("\n");
        let mut r = parse(&text);
        r.unelevated = self.unelevated;
        r.stopped = std::mem::take(&mut self.stopped);
        if r.stats.is_none() {
            r.tail = scan_output(&outs, 12);
        }
        self.log_outcome(host, &r, &outs);

        // A finding from an autostart scan is reported against the entry the
        // user can actually go and change, not the scratch file Loki read.
        if !self.staged.is_empty() {
            r.autoruns = Some((
                self.staged.len(),
                self.staged.iter().filter(|s| !s.binary).count(),
            ));
            for ev in &mut r.findings {
                relabel_autorun(&mut ev.raw, &self.staged);
            }
            // The layout has served its purpose; leaving copies of every
            // autostart program lying about would be a poor way to end a scan.
            if let Some(scan_dir) = outs.first().and_then(|p| p.parent()) {
                let _ = std::fs::remove_dir_all(scan_dir.join("autoruns"));
            }
        }

        let screen = self.screen(host, lang, None);
        self.present(lang, screen, r)
    }
}
