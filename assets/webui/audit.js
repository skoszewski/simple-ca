// The audit page of serve: the newest records of the audit log of the CA.

// auditKeys are the keys of a record shown in columns of their own.
const auditKeys = ["time", "event", "ca", "via", "actor", "client"];

// showCA draws the records of the CA on the page.
async function showCA() {
  const ca = currentCA();
  let answer;
  try {
    answer = await api("GET", "/api/entries?ca=" + encodeURIComponent(caID));
  } catch (error) {
    failed(error);
    return;
  }
  const field = (e, key) => (e.fields.find(([k]) => k === key) || ["", ""])[1];
  // The other keys of the records shown each get a column, in the order they first appear.
  const fixed = ["Time", "Event", "Actor", "Via", "Client"];
  const headings = (shown) => [...fixed,
    ...new Set(shown.flatMap((e) => e.fields.map(([k]) => k).filter((k) => !auditKeys.includes(k))))];
  const distinct = (key) => [...new Set(answer.entries.map((e) => key === "event" ? e.event : field(e, key)))]
    .filter(Boolean).sort().map((v) => [v, v]);
  const row = (e, columns) => element("tr", {},
    cell(time(e.time), "whitespace-nowrap"),
    cell(e.event, "font-mono whitespace-nowrap"),
    cell(field(e, "actor") || "-", "whitespace-nowrap"),
    cell(field(e, "via") || "-"),
    cell(field(e, "client") || "-", "font-mono"),
    ...columns.slice(fixed.length).map((key) => cell(field(e, key) || "-", "font-mono text-xs whitespace-nowrap")));
  $("ca-section").replaceChildren(...[
    heading(ca),
    answer.entries.length === 0 ? element("p", { className: "text-sm text-muted", textContent: "No records." }) :
      searchable({ items: answer.entries, row, noun: "records", headings,
        text: (e) => [e.line],
        filters: [
          { name: "event", label: "Event", multiple: true, match: (e, values) => values.includes(e.event),
            choices: [["", "all"], ...distinct("event")] },
          { name: "via", label: "Via", multiple: true, match: (e, values) => values.includes(field(e, "via")),
            choices: [["", "all"], ...distinct("via")] },
        ] }),
    answer.total > answer.entries.length ? element("p", { className: "text-sm text-muted",
      textContent: `The newest ${answer.entries.length} of ${answer.total} records of this CA; audit list prints them all.` }) : null,
  ].filter((child) => child !== null));
}

start();
