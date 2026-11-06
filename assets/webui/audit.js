// The audit page of serve: the newest records of the audit log of the server.

// auditKeys are the keys of a record shown in columns of their own.
const auditKeys = ["time", "event", "ca", "via", "actor", "client"];

// showCA draws the records of the audit log on the page.
async function showCA() {
  currentCA();
  let answer;
  try {
    answer = await api("GET", "/api/entries");
  } catch (error) {
    failed(error);
    return;
  }
  const field = (e, key) => (e.fields.find(([k]) => k === key) || ["", ""])[1];
  // The columns are the keys of the records, the fixed ones first, the others in the order they
  // first appear in the records shown.
  const fixed = ["time", "event", "ca", "actor", "via", "client"];
  const headings = (shown) => [...fixed,
    ...new Set(shown.flatMap((e) => e.fields.map(([k]) => k).filter((k) => !auditKeys.includes(k))))];
  // The root CA, whose records have no CA, is "-" to its filter, as "" clears a filter.
  const caChoice = (e) => e.ca || "-";
  const caLabel = (choice) => choice === "-" ? "root CA" : choice;
  const distinct = (key) => [...new Set(answer.entries.map((e) => key === "event" ? e.event : field(e, key)))]
    .filter(Boolean).sort().map((v) => [v, v]);
  // The cells of the columns shown, those of the fixed columns by their key.
  const fixedCells = {
    time: (e) => cell(time(e.time), "whitespace-nowrap"),
    event: (e) => cell(e.event, "font-mono whitespace-nowrap"),
    ca: (e) => cell(caLabel(caChoice(e)), "whitespace-nowrap"),
    actor: (e) => cell(field(e, "actor") || "-", "whitespace-nowrap"),
    via: (e) => cell(field(e, "via") || "-"),
    client: (e) => cell(field(e, "client") || "-", "font-mono"),
  };
  const row = (e, columns) => element("tr", {}, ...columns.map((key) =>
    fixedCells[key] ? fixedCells[key](e) : cell(field(e, key) || "-", "font-mono text-xs whitespace-nowrap")));
  $("ca-section").replaceChildren(...[
    answer.entries.length === 0 ? element("p", { className: "text-sm text-muted", textContent: "No records." }) :
      searchable({ items: answer.entries, row, noun: "records", headings, label: readable, hideable: true,
        text: (e) => [e.line],
        filters: [
          { name: "event", label: "Event", multiple: true, match: (e, values) => values.includes(e.event),
            choices: [["", "all"], ...distinct("event")] },
          { name: "issuer", label: "CA", multiple: true, match: (e, values) => values.includes(caChoice(e)),
            choices: [["", "all"], ...[...new Set(answer.entries.map(caChoice))].sort().map((c) => [c, caLabel(c)])] },
          { name: "via", label: "Via", multiple: true, match: (e, values) => values.includes(field(e, "via")),
            choices: [["", "all"], ...distinct("via")] },
        ] }),
    answer.total > answer.entries.length ? element("p", { className: "text-sm text-muted",
      textContent: `The newest ${answer.entries.length} of ${answer.total} records; audit list prints them all.` }) : null,
  ].filter((child) => child !== null));
}

start();
