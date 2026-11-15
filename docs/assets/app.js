/* PkgWatch dashboard. Vanilla JS, no dependencies, no build step.
 *
 * Everything shown comes from package registries and is therefore untrusted: it is only
 * ever inserted with textContent or as attribute values on URLs built here, never as HTML.
 */
(function () {
  "use strict";

  var REPO = "abidranesh/typosquat_-_mal_package_tracker";
  var PAGE_SIZE = 50;
  var STALE_AFTER_MS = 2 * 60 * 60 * 1000;
  var CHART_DAYS = 30;
  var SVG_NS = "http://www.w3.org/2000/svg";

  var state = {
    latest: [],
    stats: null,
    health: null,
    days: {},
    dayCache: {},
    rows: [],
    shown: PAGE_SIZE,
    open: {},
  };

  function $(id) {
    return document.getElementById(id);
  }

  /** Create an element. Children may be nodes or strings (inserted as text). */
  function el(tag, attrs, children) {
    var node = document.createElement(tag);
    Object.keys(attrs || {}).forEach(function (key) {
      if (key === "class") node.className = attrs[key];
      else if (key === "text") node.textContent = attrs[key];
      else node.setAttribute(key, attrs[key]);
    });
    (children || []).forEach(function (child) {
      if (child === null || child === undefined) return;
      node.appendChild(typeof child === "string" ? document.createTextNode(child) : child);
    });
    return node;
  }

  function clear(node) {
    while (node.firstChild) node.removeChild(node.firstChild);
  }

  function fetchJson(path) {
    return fetch(path, { cache: "no-cache" }).then(function (response) {
      if (!response.ok) throw new Error(path + " returned HTTP " + response.status);
      return response.json();
    });
  }

  // ---------------------------------------------------------------- links

  function encodeName(name) {
    return name.split("/").map(encodeURIComponent).join("/").replace(/%40/g, "@");
  }

  function registryUrl(ecosystem, name, version) {
    if (ecosystem === "npm") {
      var base = "https://www.npmjs.com/package/" + encodeName(name);
      return version ? base + "/v/" + encodeURIComponent(version) : base;
    }
    var project = "https://pypi.org/project/" + encodeURIComponent(name) + "/";
    return version ? project + encodeURIComponent(version) + "/" : project;
  }

  function detailHash(record) {
    return "#/" + record.ecosystem + "/" + encodeName(record.name) + "/" + encodeURIComponent(record.version);
  }

  function falsePositiveUrl(record) {
    var label = record.ecosystem + "/" + record.name + "@" + record.version;
    return (
      "https://github.com/" + REPO + "/issues/new?template=false-positive.yml&labels=false-positive" +
      "&title=" + encodeURIComponent("False positive: " + label) +
      "&package=" + encodeURIComponent(label)
    );
  }

  function externalLink(href, text) {
    return el("a", { href: href, rel: "noopener noreferrer", target: "_blank", text: text });
  }

  // ---------------------------------------------------------------- formatting

  function formatNumber(value) {
    return typeof value === "number" ? value.toLocaleString("en-US") : "–";
  }

  function formatDate(iso) {
    return iso ? iso.slice(0, 10) + " " + iso.slice(11, 16) + " UTC" : "unknown";
  }

  function ago(ms) {
    var minutes = Math.max(0, Math.round(ms / 60000));
    if (minutes < 1) return "just now";
    if (minutes < 60) return minutes + " min ago";
    var hours = Math.round(minutes / 60);
    if (hours < 48) return hours + " h ago";
    return Math.round(hours / 24) + " d ago";
  }

  function detectorIds(record) {
    var seen = [];
    record.findings.forEach(function (finding) {
      if (seen.indexOf(finding.id) === -1) seen.push(finding.id);
    });
    return seen;
  }

  // ---------------------------------------------------------------- header: health and theme

  function renderHealth() {
    var badge = $("health");
    var last = state.health && state.health.last_success;
    if (!last) {
      badge.textContent = "no successful run recorded";
      badge.className = "badge-health stale";
      return;
    }
    var age = Date.now() - new Date(last).getTime();
    var stale = age > STALE_AFTER_MS;
    badge.textContent = (stale ? "stale: last updated " : "last updated ") + ago(age);
    badge.className = "badge-health " + (stale ? "stale" : "ok");
    badge.title = "Last successful scan: " + formatDate(last);
  }

  function applyTheme(theme) {
    document.documentElement.setAttribute("data-theme", theme);
    var toggle = $("theme-toggle");
    toggle.textContent = theme === "dark" ? "Light mode" : "Dark mode";
    toggle.setAttribute("aria-pressed", theme === "light" ? "true" : "false");
  }

  function initTheme() {
    var saved = null;
    try {
      saved = window.localStorage.getItem("pkgwatch-theme");
    } catch (error) {
      saved = null;
    }
    applyTheme(saved === "light" ? "light" : "dark"); // dark unless the visitor chose otherwise
    $("theme-toggle").addEventListener("click", function () {
      var next = document.documentElement.getAttribute("data-theme") === "dark" ? "light" : "dark";
      applyTheme(next);
      try {
        window.localStorage.setItem("pkgwatch-theme", next);
      } catch (error) {
        /* private mode: the choice just does not persist */
      }
    });
  }

  // ---------------------------------------------------------------- stats

  function sumBuckets(buckets, keys, field) {
    return keys.reduce(function (total, key) {
      return total + ((buckets[key] && buckets[key][field]) || 0);
    }, 0);
  }

  function lastKeys(count, stepMs, length) {
    var keys = [];
    for (var i = 0; i < count; i += 1) {
      keys.push(new Date(Date.now() - i * stepMs).toISOString().slice(0, length));
    }
    return keys;
  }

  function renderStats() {
    var stats = state.stats;
    if (!stats || !stats.totals) return;
    var hours = lastKeys(24, 3600000, 13);
    var days = lastKeys(7, 86400000, 10);
    ["scanned", "flagged", "high"].forEach(function (field) {
      $("stat-" + field + "-24h").textContent = formatNumber(sumBuckets(stats.hourly || {}, hours, field));
      $("stat-" + field + "-7d").textContent = formatNumber(sumBuckets(stats.daily || {}, days, field));
      $("stat-" + field + "-all").textContent = formatNumber(stats.totals[field] || 0);
    });
  }

  // ---------------------------------------------------------------- trend chart (inline SVG)

  function svg(tag, attrs, text) {
    var node = document.createElementNS(SVG_NS, tag);
    Object.keys(attrs).forEach(function (key) {
      node.setAttribute(key, attrs[key]);
    });
    if (text !== undefined) node.textContent = text;
    return node;
  }

  function renderChart() {
    var holder = $("chart");
    clear(holder);
    var daily = (state.stats && state.stats.daily) || {};
    var days = lastKeys(CHART_DAYS, 86400000, 10).reverse();
    var series = days.map(function (day) {
      var bucket = daily[day] || {};
      return { day: day, flagged: bucket.flagged || 0, high: bucket.high || 0 };
    });
    var peak = Math.max.apply(null, series.map(function (p) { return p.flagged; }).concat([1]));
    var total = series.reduce(function (sum, p) { return sum + p.flagged; }, 0);
    var totalHigh = series.reduce(function (sum, p) { return sum + p.high; }, 0);

    var width = 720, height = 190, left = 34, right = 8, top = 12, bottom = 24;
    var plotW = width - left - right, plotH = height - top - bottom;
    var slot = plotW / series.length;
    var barW = Math.max(2, slot * 0.72);
    var root = svg("svg", {
      viewBox: "0 0 " + width + " " + height,
      role: "img",
      "aria-label":
        "Packages flagged per day over the last " + CHART_DAYS + " days: " + total +
        " in total, " + totalHigh + " of them high risk, at most " + peak + " in one day.",
    });
    root.appendChild(svg("line", { class: "axis", x1: left, y1: top + plotH, x2: width - right, y2: top + plotH }));
    root.appendChild(svg("line", { class: "axis", x1: left, y1: top, x2: left, y2: top + plotH }));
    root.appendChild(svg("text", { x: left - 6, y: top + 4, "text-anchor": "end" }, String(peak)));
    root.appendChild(svg("text", { x: left - 6, y: top + plotH, "text-anchor": "end" }, "0"));
    root.appendChild(svg("text", { x: left, y: height - 6, "text-anchor": "start" }, series[0].day));
    root.appendChild(svg("text", { x: width - right, y: height - 6, "text-anchor": "end" }, series[series.length - 1].day));

    series.forEach(function (point, index) {
      if (!point.flagged) return;
      var x = left + index * slot + (slot - barW) / 2;
      var fullH = (point.flagged / peak) * plotH;
      var highH = (point.high / peak) * plotH;
      var group = svg("g", {});
      group.appendChild(svg("title", {}, point.day + ": " + point.flagged + " flagged, " + point.high + " high risk"));
      group.appendChild(svg("rect", { class: "bar", x: x, y: top + plotH - fullH, width: barW, height: fullH, rx: 1.5 }));
      if (point.high) {
        group.appendChild(svg("rect", { class: "bar-high", x: x, y: top + plotH - highH, width: barW, height: highH, rx: 1.5 }));
      }
      root.appendChild(group);
    });
    holder.appendChild(root);
    $("chart-summary").textContent = total
      ? total + " packages flagged in the last " + CHART_DAYS + " days, " + totalHigh + " of them high risk."
      : "No packages flagged in the last " + CHART_DAYS + " days yet.";
  }

  // ---------------------------------------------------------------- reasons and details

  function reasonList(record) {
    var list = el("ul", { class: "reasons" });
    record.findings.forEach(function (finding) {
      var item = el("li", { class: "w-" + finding.severity }, [
        el("div", { class: "reason-head" }, [
          el("code", { text: finding.id }),
          el("span", { class: "weight", text: "+" + finding.weight + " (" + finding.severity + ")" }),
        ]),
        el("p", { text: finding.message }),
      ]);
      if (finding.evidence) {
        item.appendChild(
          el("div", { class: "evidence" }, [
            el("div", { class: "path", text: finding.evidence.path }),
            el("pre", { text: finding.evidence.snippet }),
          ])
        );
      }
      list.appendChild(item);
    });
    return list;
  }

  function linkRow(record, includeDetail) {
    var links = el("div", { class: "links" }, [
      externalLink(registryUrl(record.ecosystem, record.name, record.version), "Registry page"),
    ]);
    (record.targets || []).forEach(function (target) {
      var isPackage = target.charAt(0) !== "@" || target.indexOf("/") !== -1;
      links.appendChild(
        isPackage
          ? externalLink(registryUrl(record.ecosystem, target), "Possible target: " + target)
          : el("span", { class: "muted", text: "Possible target scope: " + target })
      );
    });
    if (includeDetail) links.appendChild(el("a", { href: detailHash(record), text: "Permalink" }));
    links.appendChild(externalLink(falsePositiveUrl(record), "Report a false positive"));
    return links;
  }

  function severityBadge(record) {
    return el("span", {
      class: "sev sev-" + record.severity,
      text: record.severity + " " + record.score,
      title: "Risk score " + record.score + " of 100",
    });
  }

  // ---------------------------------------------------------------- findings table

  function currentFilters() {
    return {
      search: $("f-search").value.trim().toLowerCase(),
      ecosystem: $("f-ecosystem").value,
      severity: $("f-severity").value,
      detector: $("f-detector").value,
      day: $("f-day").value,
    };
  }

  function matches(record, filters) {
    if (filters.ecosystem && record.ecosystem !== filters.ecosystem) return false;
    if (filters.severity && record.severity !== filters.severity) return false;
    if (filters.detector && detectorIds(record).indexOf(filters.detector) === -1) return false;
    if (!filters.search) return true;
    var haystack = [record.name, record.version, record.description || ""]
      .concat(record.targets || [])
      .concat(record.findings.map(function (f) { return f.id + " " + f.message; }))
      .join(" ")
      .toLowerCase();
    return haystack.indexOf(filters.search) !== -1;
  }

  function buildRow(record, index) {
    var key = record.key;
    var detailsId = "details-" + index;
    var button = el("button", {
      type: "button",
      class: "expand",
      "aria-expanded": state.open[key] ? "true" : "false",
      "aria-controls": detailsId,
      text: state.open[key] ? "Hide reasons" : "Show reasons",
    });
    button.setAttribute("aria-label", (state.open[key] ? "Hide" : "Show") + " reasons for " + record.name + " " + record.version);
    var chips = el("div", { class: "chips" });
    detectorIds(record).forEach(function (id) {
      chips.appendChild(el("span", { class: "chip", text: id }));
    });
    var row = el("tr", { class: "row" }, [
      el("td", { class: "pkg" }, [
        el("a", { href: detailHash(record), text: record.name }),
        el("span", { class: "ver", text: " " + record.version }),
      ]),
      el("td", {}, [el("span", { class: "eco", text: record.ecosystem === "pypi" ? "PyPI" : "npm" })]),
      el("td", {}, [severityBadge(record)]),
      el("td", { class: "dets" }, [chips]),
      el("td", { class: "when", text: (record.published_at || record.scanned_at).slice(0, 10) }),
      el("td", {}, [button]),
    ]);
    var details = el("tr", { class: "details", id: detailsId }, [
      el("td", { colspan: "6" }, [reasonList(record), linkRow(record, true)]),
    ]);
    details.hidden = !state.open[key];
    button.addEventListener("click", function () {
      state.open[key] = !state.open[key];
      details.hidden = !state.open[key];
      button.setAttribute("aria-expanded", state.open[key] ? "true" : "false");
      button.textContent = state.open[key] ? "Hide reasons" : "Show reasons";
      button.setAttribute("aria-label", (state.open[key] ? "Hide" : "Show") + " reasons for " + record.name + " " + record.version);
    });
    return [row, details];
  }

  function renderTable() {
    var filters = currentFilters();
    var source = filters.day ? state.dayCache[filters.day] || [] : state.latest;
    state.rows = source.filter(function (record) { return matches(record, filters); });
    var body = $("findings-body");
    clear(body);
    state.rows.slice(0, state.shown).forEach(function (record, index) {
      buildRow(record, index).forEach(function (node) { body.appendChild(node); });
    });
    var shown = Math.min(state.shown, state.rows.length);
    $("result-count").textContent =
      "Showing " + shown + " of " + state.rows.length + " findings" +
      (filters.day ? " published on " + filters.day : " (most recent " + state.latest.length + ")") + ".";
    $("empty").hidden = state.rows.length !== 0;
    $("show-more").hidden = state.rows.length <= state.shown;
  }

  function loadDay(day) {
    if (state.dayCache[day]) return Promise.resolve(state.dayCache[day]);
    var parts = day.split("-");
    return fetchJson("data/findings/" + parts[0] + "/" + parts[1] + "/" + parts[2] + ".json").then(function (doc) {
      state.dayCache[day] = doc.findings || [];
      return state.dayCache[day];
    });
  }

  function onFiltersChanged() {
    state.shown = PAGE_SIZE;
    var day = $("f-day").value;
    if (!day) return renderTable();
    $("result-count").textContent = "Loading " + day + "…";
    loadDay(day).then(renderTable, function (error) {
      showError("Could not load findings for " + day + ": " + error.message);
      renderTable();
    });
  }

  function populateFilterOptions() {
    var detector = $("f-detector");
    var ids = {};
    state.latest.forEach(function (record) {
      detectorIds(record).forEach(function (id) { ids[id] = true; });
    });
    ((state.stats && state.stats.top_detectors) || []).forEach(function (entry) { ids[entry.id] = true; });
    Object.keys(ids).sort().forEach(function (id) {
      detector.appendChild(el("option", { value: id, text: id }));
    });
    var day = $("f-day");
    Object.keys(state.days).sort().reverse().forEach(function (date) {
      day.appendChild(el("option", { value: date, text: date + " (" + state.days[date] + ")" }));
    });
  }

  // ---------------------------------------------------------------- detail view

  function findRecord(ecosystem, name, version) {
    var key = ecosystem + "/" + name + "/" + version;
    function inList(list) {
      for (var i = 0; i < list.length; i += 1) if (list[i].key === key) return list[i];
      return null;
    }
    var hit = inList(state.latest);
    if (hit) return Promise.resolve(hit);
    // Not among the latest 500: walk the daily files, newest first.
    var days = Object.keys(state.days).sort().reverse();
    function next(index) {
      if (index >= days.length) return Promise.resolve(null);
      return loadDay(days[index]).then(
        function (list) { return inList(list) || next(index + 1); },
        function () { return next(index + 1); }
      );
    }
    return next(0);
  }

  function renderDetail(ecosystem, name, version) {
    var heading = $("detail-heading");
    var body = $("detail-body");
    heading.textContent = name + " " + version;
    clear(body);
    body.appendChild(el("p", { class: "muted", text: "Loading…" }));
    findRecord(ecosystem, name, version).then(function (record) {
      clear(body);
      if (!record) {
        body.appendChild(
          el("p", { class: "notice" }, [
            "No listing was found for this package version. It may never have been flagged, " +
              "or its listing is older than the 365-day retention window. Not being listed does not mean a package was checked and found safe.",
          ])
        );
        body.appendChild(el("div", { class: "links" }, [externalLink(registryUrl(ecosystem, name, version), "Registry page")]));
        return;
      }
      var meta = el("dl", { class: "detail-meta" }, [
        el("dt", { text: "Assessment" }),
        el("dd", {}, [severityBadge(record), " suspicious, risk score " + record.score + " of 100"]),
        el("dt", { text: "Ecosystem" }),
        el("dd", { text: record.ecosystem === "pypi" ? "PyPI" : "npm" }),
        el("dt", { text: "Published" }),
        el("dd", { text: formatDate(record.published_at) }),
        el("dt", { text: "Scanned" }),
        el("dd", { text: formatDate(record.scanned_at) }),
        el("dt", { text: "Description" }),
        el("dd", { text: record.description || "(none)" }),
      ]);
      body.appendChild(meta);
      body.appendChild(el("h2", { text: "Why it was listed" }));
      body.appendChild(reasonList(record));
      body.appendChild(linkRow(record, false));
      body.appendChild(
        el("p", { class: "muted small", text: "This is an automated lead for review, based on static analysis only. It is not a verdict." })
      );
    });
  }

  // ---------------------------------------------------------------- routing

  function show(view) {
    ["findings", "detail", "about"].forEach(function (name) {
      $("view-" + name).hidden = name !== view;
    });
    Array.prototype.forEach.call(document.querySelectorAll("nav a[data-nav]"), function (link) {
      if (link.getAttribute("data-nav") === view) link.setAttribute("aria-current", "page");
      else link.removeAttribute("aria-current");
    });
  }

  function route() {
    var parts = window.location.hash.replace(/^#\/?/, "").split("/").filter(Boolean);
    var title = "PkgWatch: suspicious new packages on npm and PyPI";
    if (parts[0] === "about") {
      show("about");
      title = "About and methodology · PkgWatch";
    } else if ((parts[0] === "npm" || parts[0] === "pypi") && parts.length >= 3) {
      var version, name;
      try {
        version = decodeURIComponent(parts[parts.length - 1]);
        name = parts.slice(1, -1).map(decodeURIComponent).join("/");
      } catch (error) {
        show("findings");
        return;
      }
      show("detail");
      renderDetail(parts[0], name, version);
      title = name + " " + version + " · PkgWatch";
    } else {
      show("findings");
    }
    document.title = title;
    if (window.location.hash) {
      window.scrollTo(0, 0);
      $("main").focus({ preventScroll: true });
    }
  }

  // ---------------------------------------------------------------- start-up

  function showError(message) {
    var box = $("load-error");
    box.textContent = message;
    box.hidden = false;
  }

  function optional(path, fallback) {
    return fetchJson(path).catch(function () { return fallback; });
  }

  function init() {
    initTheme();
    $("filters").addEventListener("input", onFiltersChanged);
    $("filters").addEventListener("change", onFiltersChanged);
    $("filters").addEventListener("submit", function (event) { event.preventDefault(); });
    $("filters").addEventListener("reset", function () { window.setTimeout(onFiltersChanged, 0); });
    $("show-more").addEventListener("click", function () {
      state.shown += PAGE_SIZE;
      renderTable();
    });
    window.addEventListener("hashchange", route);

    Promise.all([
      fetchJson("data/latest.json"),
      optional("data/stats.json", null),
      optional("data/health.json", null),
      optional("data/findings/index.json", { days: {} }),
    ]).then(
      function (results) {
        state.latest = results[0].findings || [];
        state.stats = results[1];
        state.health = results[2];
        state.days = (results[3] && results[3].days) || {};
        renderHealth();
        window.setInterval(renderHealth, 60000);
        renderStats();
        renderChart();
        populateFilterOptions();
        renderTable();
        route();
      },
      function (error) {
        showError("Could not load the findings data (" + error.message + "). Try reloading in a moment.");
        $("health").textContent = "data unavailable";
        $("health").className = "badge-health stale";
        route();
      }
    );
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
