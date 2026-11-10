# Analyst notes

One optional file per week, named after the report: `2026-W46.md`. reports.html shows it in the
"Analyst notes" box; weeks without a file show no box. Push to main and Pages deploys it
(the workflow lists the files in `notes/index.json`, which reports.html reads).

Supported Markdown (rendered as plain DOM nodes, never as HTML): `#`, `##` and `###` headings,
paragraphs, `-` lists, fenced code blocks, inline `code`, `**bold**` and `[links](https://...)` (https only).

Everything here is public: defang IPs and URLs (`hxxp[:]//192[.]0[.]2[.]1`) and never paste raw log lines
with source IPs.
