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
  // The other keys of a record are listed with their values, a pair on each line.
  const details = (e) => {
    const pairs = e.fields.filter(([k]) => !auditKeys.includes(k));
    return pairs.length === 0 ? "-" : element("dl", { className: "grid grid-cols-[6rem_1fr] gap-x-3 gap-y-0.5 text-xs" },
      ...pairs.flatMap(([k, v]) => [element("dt", { className: "text-muted", textContent: k }),
        element("dd", { className: "font-mono break-all", textContent: v || "-" })]));
  };
  const distinct = (key) => [...new Set(answer.entries.map((e) => key === "event" ? e.event : field(e, key)))]
    .filter(Boolean).sort().map((v) => [v, v]);
  const row = (e) => element("tr", { className: "align-top" },
    cell(time(e.time), "whitespace-nowrap"),
    cell(e.event, "font-mono whitespace-nowrap"),
    cell(field(e, "actor") || "-"),
    cell(field(e, "via") || "-"),
    cell(field(e, "client") || "-", "font-mono"),
    cell(details(e)));
  $("ca-section").replaceChildren(...[
    heading(ca),
    answer.entries.length === 0 ? element("p", { className: "text-sm text-muted", textContent: "No records." }) :
      searchable({ items: answer.entries, row, noun: "records", headings: ["Time", "Event", "Actor", "Via", "Client", "Details"],
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
