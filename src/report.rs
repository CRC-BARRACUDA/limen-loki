//! Reading what the scanner wrote.
//!
//! Loki-RS writes one JSON object per line; this turns that stream into
//! findings, counts, and the summary a finished scan ends with.

use crate::*;

/// One parsed line of the report.
///
/// Kept as the raw `Value` plus the few fields worth indexing: the schema has
/// some twenty optional fields and more will arrive, so the detail view reads
/// from the original object rather than from anything this struct chose to keep.
#[derive(Clone)]
pub(crate) struct Event {
    pub(crate) raw: Value,
    pub(crate) level: String,
    pub(crate) event_type: String,
    pub(crate) score: f64,
}

impl Event {
    pub(crate) fn parse(line: &str) -> Option<Self> {
        let mut raw: Value = serde_json::from_str(line).ok()?;
        // The scanner reports paths exactly as it walked them, and a target it
        // would otherwise skip is handed over with a doubled leading slash (see
        // `walkable`). Undone here, once, so nothing downstream — the table, the
        // detail view, a path the user copies — has to know that happened.
        if let Some(rest) = raw
            .get("file_path")
            .and_then(Value::as_str)
            .and_then(|p| p.strip_prefix("//"))
        {
            raw["file_path"] = Value::String(format!("/{rest}"));
        }
        Some(Event {
            level: str_of(&raw, "level").unwrap_or_default(),
            event_type: str_of(&raw, "event_type").unwrap_or_default(),
            score: raw.get("score").and_then(Value::as_f64).unwrap_or(0.0),
            raw,
        })
    }

    /// Whether this line is a finding rather than a scan boundary or a log line.
    pub(crate) fn is_match(&self) -> bool {
        matches!(self.event_type.as_str(), "file_match" | "process_match")
    }

    /// What the finding is about: a path for a file, `name (pid)` for a process.
    pub(crate) fn subject(&self) -> String {
        if let Some(p) = str_of(&self.raw, "file_path") {
            return p;
        }
        match (
            self.raw.get("pid").and_then(Value::as_u64),
            str_of(&self.raw, "process_name"),
        ) {
            (Some(pid), Some(name)) => format!("{name} ({pid})"),
            (Some(pid), None) => format!("pid {pid}"),
            _ => str_of(&self.raw, "message").unwrap_or_default(),
        }
    }

    /// The rules that matched, joined for the table's one-line summary.
    pub(crate) fn rules(&self) -> String {
        let Some(rs) = self.raw.get("reasons").and_then(Value::as_array) else {
            return str_of(&self.raw, "message").unwrap_or_default();
        };
        rs.iter()
            .filter_map(|r| str_of(r, "message"))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// Which finding, in which report: the `report:index` a row carries.
///
/// The module decides what a row id is and the host sends it back untouched, so
/// this is where a click stops meaning "number two of whatever was scanned
/// last". The index is into the *filtered* list the row was drawn from, which is
/// why the levels ride along with it.
pub(crate) struct RowId {
    pub(crate) report: u64,
    pub(crate) index: usize,
}

impl RowId {
    /// The id row `index` of report `report` carries.
    pub(crate) fn of(report: u64, index: usize) -> String {
        format!("{report}:{index}")
    }

    /// Read one back, or `None` if it is not one of ours.
    pub(crate) fn parse(s: &str) -> Option<RowId> {
        let (report, index) = s.split_once(':')?;
        Some(RowId {
            report: report.parse().ok()?,
            index: index.parse().ok()?,
        })
    }
}

pub(crate) fn str_of(v: &Value, key: &str) -> Option<String> {
    v.get(key).and_then(Value::as_str).map(str::to_string)
}

/// The tallies Loki prints when a scan ends.
///
/// It reports them as one English sentence, which is no use in another language
/// and no use as data. The numbers are pulled out so the module can say them in
/// its own words — and show them or not, depending on how much detail was asked
/// for.
#[derive(Default, Clone)]
pub(crate) struct Stats {
    pub(crate) files: u64,
    pub(crate) files_matched: u64,
    pub(crate) procs: u64,
    pub(crate) procs_matched: u64,
    /// Seconds rather than the string Loki printed, so they can be added up and
    /// formatted for whoever is reading them.
    pub(crate) secs: f64,
}

impl Stats {
    /// Fold another scan's tallies into these.
    fn merge(&mut self, other: &Stats) {
        self.files += other.files;
        self.files_matched += other.files_matched;
        self.procs += other.procs;
        self.procs_matched += other.procs_matched;
        self.secs += other.secs;
    }
}

/// `4.8` -> `4.8s`, `92.0` -> `1m 32s`.
pub(crate) fn fmt_secs(secs: f64) -> String {
    if secs < 60.0 {
        format!("{secs:.1}s")
    } else {
        format!("{}m {}s", (secs / 60.0) as u64, (secs % 60.0) as u64)
    }
}

impl Stats {
    /// Read `Files scanned: 0 Matched: 0 | Processes scanned: 0 Matched: 0 …
    /// Scan Duration: 4.80s`.
    ///
    /// Positional rather than regex: the two `Matched:` counts are told apart by
    /// which section they follow, so the file count cannot be read as the
    /// process one.
    pub(crate) fn parse(msg: &str) -> Option<Self> {
        let num_after = |hay: &str, key: &str| -> Option<u64> {
            let i = hay.find(key)? + key.len();
            hay[i..]
                .trim_start()
                .split(|c: char| !c.is_ascii_digit())
                .next()
                .and_then(|d| d.parse().ok())
        };
        let files_part = msg.split('|').next().unwrap_or("");
        let procs_part = msg.split('|').nth(1).unwrap_or("");
        // "4.80s" -> 4.80. Anything else leaves it at zero rather than guessing.
        let secs = msg
            .find("Scan Duration:")
            .and_then(|i| {
                msg[i + "Scan Duration:".len()..]
                    .split_whitespace()
                    .next()
                    .map(|d| d.trim_end_matches('s'))
                    .and_then(|d| d.parse::<f64>().ok())
            })
            .unwrap_or(0.0);
        Some(Stats {
            files: num_after(files_part, "Files scanned:")?,
            files_matched: num_after(files_part, "Matched:").unwrap_or(0),
            procs: num_after(procs_part, "Processes scanned:").unwrap_or(0),
            procs_matched: num_after(procs_part, "Matched:").unwrap_or(0),
            secs,
        })
    }
}

/// `2026-08-03T19:44:38.546148389+00:00` -> `2026-08-03 19:44:38`.
///
/// The offset and the nanoseconds are noise on screen; nobody reading a scan
/// report needs the ninth decimal place of when it started.
pub(crate) fn pretty_time(ts: &str) -> String {
    let Some(t) = ts.find('T') else {
        return ts.to_string();
    };
    // Cut at the fractional seconds or the offset, whichever comes first. The
    // search starts after the `T` because the date half uses `-` as a separator
    // and a negative offset would otherwise be found inside the year.
    let time = &ts[t + 1..];
    let cut = time.find(['.', '+', '-', 'Z']).unwrap_or(time.len());
    format!("{} {}", &ts[..t], &time[..cut])
}

/// A parsed report: the findings, plus whatever the scan boundaries told us.
#[derive(Default)]
pub(crate) struct Report {
    pub(crate) findings: Vec<Event>,
    /// Level -> how many findings carried it, for the filter chips.
    pub(crate) counts: BTreeMap<String, usize>,
    pub(crate) hostname: String,
    pub(crate) started: String,
    pub(crate) ended: String,
    pub(crate) summary: String,
    pub(crate) stats: Option<Stats>,
    /// The scan ran unprivileged, so anything it could not read was skipped
    /// without being counted.
    pub(crate) unelevated: bool,
    /// Stopping did not stop it: the scan is elevated and still running.
    pub(crate) still_running: bool,
    /// The user pressed Stop. It did not finish, but that is what was asked for
    /// — so it is not a failure, and saying so is not the same as saying the
    /// machine is clean.
    pub(crate) stopped: bool,
    /// The last thing the scanner said, kept only when it did not finish — then
    /// it is the whole diagnosis, and telling the user to go and find it
    /// elsewhere is no help at all.
    pub(crate) tail: Vec<String>,
    /// An autostart scan: how many entries were checked, and how many named a
    /// program that could not be read. The second number matters — autoruns
    /// skips keys it cannot see without admin, and a command whose program is
    /// missing was only ever checked as text.
    pub(crate) autoruns: Option<(usize, usize)>,
    /// Lines that were not valid JSON. A scan killed part-way leaves a truncated
    /// last line, so this is expected rather than exceptional — but it is
    /// reported, because silently dropping input is how a reader lies.
    pub(crate) skipped: usize,
}

/// Parse a report.
///
/// Every line is independent, so a bad one is skipped rather than failing the
/// file: a report from an interrupted scan is exactly when you most want to read
/// what did get written.
///
pub(crate) fn parse(text: &str) -> Report {
    let mut r = Report::default();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Some(ev) = Event::parse(line) else {
            r.skipped += 1;
            continue;
        };
        match ev.event_type.as_str() {
            "scan_start" => {
                r.hostname = str_of(&ev.raw, "hostname").unwrap_or_default();
                // The earliest start and the latest finish bracket the whole run.
                let started = str_of(&ev.raw, "timestamp").unwrap_or_default();
                if r.started.is_empty() || started < r.started {
                    r.started = started;
                }
            }
            "scan_end" => {
                let ended = str_of(&ev.raw, "timestamp").unwrap_or_default();
                if ended > r.ended {
                    r.ended = ended;
                }
                r.summary = str_of(&ev.raw, "message").unwrap_or_default();
                if let Some(s) = Stats::parse(&r.summary) {
                    match &mut r.stats {
                        Some(acc) => acc.merge(&s),
                        None => r.stats = Some(s),
                    }
                }
            }
            _ => {}
        }
        if ev.is_match() {
            *r.counts.entry(ev.level.clone()).or_insert(0) += 1;
            r.findings.push(ev);
        }
    }
    // Worst first — that is the order anyone reading a scan report wants.
    r.findings.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    r
}
