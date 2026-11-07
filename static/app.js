/**
 * SentinelTrap: Enterprise Threat Intelligence & Attack Surface Observer
 * Frontend Controller: Real-time WebSocket Stream, Bilingual i18n (EN/ID),
 * Monochromatic Equirectangular World Projection Map, and Forensic Log Inspector.
 */

(() => {
  "use strict";

  // ---------------------------------------------------------------------------
  // 1. Bilingual Localization Dictionary (EN default | ID)
  // ---------------------------------------------------------------------------
  const I18N = {
    en: {
      appSubtitle: "Threat Intelligence Honeypot & Global Attack Surface Observer",
      statusLive: "SENSOR LIVE",
      statusIdle: "SENSOR IDLE",
      uptimeLabel: "UPTIME",
      listenersLabel: "ACTIVE LISTENERS",
      kpiTotalEventsTitle: "Total Ingestion Events",
      kpiTotalEventsSub: "Cumulative honeypot packets & sessions captured",
      kpiUniqueIpsTitle: "Unique Origin IPs",
      kpiUniqueIpsSub: "Distinct adversarial IPv4 sources fingerprinted",
      kpiCriticalTitle: "High-Severity Breaches",
      kpiCriticalSub: "Critical SQLi, RCE, LFI & botnet dropper payloads",
      kpiEntropyTitle: "Average Request Entropy",
      kpiEntropySub: "Mean Shannon entropy (bits/byte) across payloads",
      mapHeaderTitle: "Global Attack Surface Projection",
      mapHeaderSubtitle: "Equirectangular WGS84 coordinate telemetry — active adversarial origins",
      mapLegendCritical: "Critical Exploit (RCE / SQLi / LFI)",
      mapLegendMedium: "Medium Probe (Brute-Force / Recon)",
      mapLegendLow: "Low Severity (Banner / Port Scan)",
      mapSensorLabel: "Honeypot Collector Node",
      topOriginsTitle: "Top Source Jurisdictions",
      protocolSplitTitle: "Protocol Telemetry Split",
      actionExportJson: "Export JSON",
      actionExportCsv: "Export CSV (STIX compliant)",
      actionSimulateBurst: "Inject Test Burst (+5)",
      actionClearDb: "Clear Database",
      filterSearchPlaceholder: "Filter by IP, PTR, payload, credentials, or country...",
      filterAllSeverities: "All Severities",
      filterCriticalOnly: "Critical",
      filterMediumOnly: "Medium",
      filterLowOnly: "Low",
      filterAllProtocols: "All Protocols",
      tableHeaderTitle: "Real-Time Forensic Telemetry Stream",
      tableHeaderSub: "Live packet & session inspection captured on ports 2222 (SSH) and 8080 (HTTP-API)",
      colTimestamp: "Timestamp (UTC)",
      colSourceIp: "Source IP & Reverse PTR",
      colGeo: "Geo / Jurisdiction",
      colProtocol: "Targeted Protocol",
      colPayload: "Credentials & Captured Payload",
      colEntropy: "Entropy",
      colSeverity: "Severity",
      emptyTableText: "No telemetry events match the active filter criteria.",
      confirmClearText: "Are you sure you want to purge all captured forensic events from sentinel.db?",
      toastCleared: "Database purged. Telemetry counters reset.",
      toastBurst: "Dispatched 5 simulated multi-vector attacks to honeypot sockets.",
      severityMap: {
        Critical: "CRITICAL",
        Medium: "MEDIUM",
        Low: "LOW"
      }
    },
    id: {
      appSubtitle: "Honeypot Intelijen Ancaman & Pengamat Permukaan Serangan Global",
      statusLive: "SENSOR AKTIF",
      statusIdle: "SENSOR SIAGA",
      uptimeLabel: "WAKTU AKTIF",
      listenersLabel: "PORT PEMANTAU",
      kpiTotalEventsTitle: "Total InsidenTerekam",
      kpiTotalEventsSub: "Akumulasi paket & sesi honeypot yang berhasil ditangkap",
      kpiUniqueIpsTitle: "IP Sumber Unik",
      kpiUniqueIpsSub: "Alamat IPv4 penyerang berbeda yang teridentifikasi",
      kpiCriticalTitle: "Pelanggaran Tingkat Tinggi",
      kpiCriticalSub: "Payload eksploitasi kritis SQLi, RCE, LFI & dropper botnet",
      kpiEntropyTitle: "Rata-rata Entropi Request",
      kpiEntropySub: "Rata-rata entropi Shannon (bit/karakter) pada payload",
      mapHeaderTitle: "Proyeksi Permukaan Serangan Global",
      mapHeaderSubtitle: "Telemetri koordinat WGS84 secara langsung — titik asal serangan aktif",
      mapLegendCritical: "Eksploitasi Kritis (RCE / SQLi / LFI)",
      mapLegendMedium: "Percobaan Menengah (Brute-Force / Recon)",
      mapLegendLow: "Tingkat Rendah (Pemindaian Port / Banner)",
      mapSensorLabel: "Node Kolektor Honeypot",
      topOriginsTitle: "Yurisdiksi Sumber Teratas",
      protocolSplitTitle: "Distribusi Protokol Target",
      actionExportJson: "Ekspor JSON",
      actionExportCsv: "Ekspor CSV (Standar STIX)",
      actionSimulateBurst: "Uji Serangan (+5)",
      actionClearDb: "Bersihkan Database",
      filterSearchPlaceholder: "Cari berdasarkan IP, PTR, payload, kredensial, atau negara...",
      filterAllSeverities: "Semua Tingkat Risiko",
      filterCriticalOnly: "Kritis (Critical)",
      filterMediumOnly: "Menengah (Medium)",
      filterLowOnly: "Rendah (Low)",
      filterAllProtocols: "Semua Protokol",
      tableHeaderTitle: "Aliran Telemetri Forensik Real-Time",
      tableHeaderSub: "Inspeksi paket & sesi langsung pada port 2222 (SSH) dan 8080 (HTTP-API)",
      colTimestamp: "Waktu (UTC)",
      colSourceIp: "IP Sumber & Reverse PTR",
      colGeo: "Negara / Lokasi",
      colProtocol: "Protokol Target",
      colPayload: "Kredensial & Payload Tertangkap",
      colEntropy: "Entropi",
      colSeverity: "Tingkat Risiko",
      emptyTableText: "Tidak ada data telemetri yang sesuai dengan filter aktif.",
      confirmClearText: "Apakah Anda yakin ingin menghapus seluruh riwayat insiden forensik dari sentinel.db?",
      toastCleared: "Database dibersihkan. Metrik telemetri diatur ulang.",
      toastBurst: "5 simulasi serangan multi-vektor berhasil dikirim ke sensor honeypot.",
      severityMap: {
        Critical: "KRITIS",
        Medium: "MENENGAH",
        Low: "RENDAH"
      }
    }
  };

  // Simplified world continental landmass polygons [lon, lat] for crisp dark-minimalist canvas rendering
  const WORLD_LANDMASS_POLYGONS = [
    // North America
    [[-168,65],[-140,70],[-125,70],[-110,65],[-95,68],[-80,63],[-65,60],[-55,48],[-68,44],[-75,35],[-81,25],[-90,20],[-84,9],[-78,8],[-95,16],[-105,20],[-117,32],[-124,48],[-140,59],[-165,60]],
    // Greenland
    [[-55,60],[-44,60],[-20,70],[-18,81],[-45,83],[-65,76]],
    // South America
    [[-78,9],[-62,10],[-50,0],[-35,-6],[-38,-15],[-48,-28],[-58,-38],[-68,-54],[-74,-50],[-72,-35],[-70,-18],[-80,-4]],
    // Europe
    [[-10,36],[-9,43],[-4,48],[2,51],[8,54],[10,58],[5,62],[16,69],[30,70],[40,66],[55,60],[50,45],[35,45],[28,41],[24,37],[15,38],[12,44],[5,43],[0,38]],
    // United Kingdom & Ireland
    [[-8,52],[-5,58],[-2,57],[1,51],[-5,50]],
    // Africa
    [[-17,15],[-13,28],[-6,35],[10,37],[25,32],[33,31],[43,12],[51,11],[40,-10],[35,-25],[20,-35],[17,-28],[12,-15],[9,-2],[5,5],[-8,5]],
    // Asia
    [[35,45],[50,45],[55,60],[75,72],[105,75],[140,70],[170,65],[160,55],[142,50],[135,35],[122,30],[120,22],[108,18],[104,1],[100,14],[90,22],[80,8],[72,20],[62,25],[55,22],[48,30],[36,35]],
    // Japan
    [[130,31],[136,35],[141,41],[145,44],[141,36],[132,32]],
    // Indonesia / Maritime SE Asia
    [[95,5],[105,-6],[115,-8],[120,-5],[114,4],[102,2]],
    [[120,-2],[135,-4],[141,-8],[132,-8]],
    // Australia
    [[114,-22],[122,-16],[136,-12],[142,-11],[150,-22],[153,-28],[148,-38],[138,-35],[128,-32],[115,-34]],
    // New Zealand
    [[166,-46],[174,-36],[178,-38],[170,-46]]
  ];

  // Collector Sensor Home Location (Jakarta / SE Asia Regional SOC Node)
  const SENSOR_HOME = { lat: -6.2088, lon: 106.8456, label: "SOC-NODE-APAC-01" };

  // Application State
  const state = {
    lang: localStorage.getItem("sentinel_lang") || "en",
    status: "live",
    uptimeSeconds: 0,
    events: [],
    metrics: {
      total_events: 0,
      unique_ips: 0,
      critical_breaches: 0,
      avg_entropy: 0.0,
      protocols: {},
      top_countries: []
    },
    filters: {
      search: "",
      severity: "all",
      protocol: "all"
    },
    hoveredPoint: null,
    pulseAnimations: [] // { lat, lon, severity, bornAt }
  };

  // DOM Elements cache
  const dom = {};

  function cacheDom() {
    dom.langBtnEn = document.getElementById("lang-btn-en");
    dom.langBtnId = document.getElementById("lang-btn-id");
    dom.statusDot = document.getElementById("status-dot");
    dom.statusText = document.getElementById("status-text");
    dom.uptimeValue = document.getElementById("uptime-value");
    dom.kpiTotal = document.getElementById("kpi-total-events");
    dom.kpiUnique = document.getElementById("kpi-unique-ips");
    dom.kpiCritical = document.getElementById("kpi-critical-breaches");
    dom.kpiEntropy = document.getElementById("kpi-avg-entropy");
    dom.topOriginsList = document.getElementById("top-origins-list");
    dom.protocolSplitContainer = document.getElementById("protocol-split-container");
    dom.searchInput = document.getElementById("filter-search");
    dom.severitySelect = document.getElementById("filter-severity");
    dom.protocolSelect = document.getElementById("filter-protocol");
    dom.tableBody = document.getElementById("forensic-table-body");
    dom.eventCounterBadge = document.getElementById("table-row-count");
    dom.mapCanvas = document.getElementById("threat-map-canvas");
    dom.mapTooltip = document.getElementById("map-tooltip");
    dom.btnExportJson = document.getElementById("btn-export-json");
    dom.btnExportCsv = document.getElementById("btn-export-csv");
    dom.btnSimulateBurst = document.getElementById("btn-simulate-burst");
    dom.btnClearDb = document.getElementById("btn-clear-db");
    dom.toastContainer = document.getElementById("toast-notification");
    dom.toastMessage = document.getElementById("toast-message");
  }

  // ---------------------------------------------------------------------------
  // 2. Internationalization (i18n) Engine
  // ---------------------------------------------------------------------------
  function setLanguage(lang) {
    if (!I18N[lang]) return;
    state.lang = lang;
    localStorage.setItem("sentinel_lang", lang);

    // Toggle active styling on language switcher buttons
    if (lang === "en") {
      dom.langBtnEn.className = "px-2.5 py-1 text-xs font-semibold rounded bg-slate-800 text-slate-100 border border-slate-700";
      dom.langBtnId.className = "px-2.5 py-1 text-xs font-medium rounded text-slate-400 hover:text-slate-200";
    } else {
      dom.langBtnId.className = "px-2.5 py-1 text-xs font-semibold rounded bg-slate-800 text-slate-100 border border-slate-700";
      dom.langBtnEn.className = "px-2.5 py-1 text-xs font-medium rounded text-slate-400 hover:text-slate-200";
    }

    const dict = I18N[lang];
    document.querySelectorAll("[data-i18n]").forEach((el) => {
      const key = el.getAttribute("data-i18n");
      if (dict[key]) {
        el.textContent = dict[key];
      }
    });

    document.querySelectorAll("[data-i18n-placeholder]").forEach((el) => {
      const key = el.getAttribute("data-i18n-placeholder");
      if (dict[key]) {
        el.setAttribute("placeholder", dict[key]);
      }
    });

    updateStatusIndicator();
    renderForensicTable(false);
    renderSidePanels();
  }

  function updateStatusIndicator() {
    const dict = I18N[state.lang];
    if (state.status === "live") {
      dom.statusDot.className = "h-2 w-2 rounded-full bg-emerald-500";
      dom.statusText.textContent = dict.statusLive;
      dom.statusText.className = "text-xs font-semibold tracking-wider text-emerald-400 font-mono-code";
    } else {
      dom.statusDot.className = "h-2 w-2 rounded-full bg-amber-500";
      dom.statusText.textContent = dict.statusIdle;
      dom.statusText.className = "text-xs font-semibold tracking-wider text-amber-400 font-mono-code";
    }
  }

  function formatUptime(totalSec) {
    const hrs = String(Math.floor(totalSec / 3600)).padStart(2, "0");
    const mins = String(Math.floor((totalSec % 3600) / 60)).padStart(2, "0");
    const secs = String(totalSec % 60).padStart(2, "0");
    return `${hrs}:${mins}:${secs}`;
  }

  // ---------------------------------------------------------------------------
  // 3. Metrics & Side Breakdown Rendering
  // ---------------------------------------------------------------------------
  function renderMetrics() {
    const m = state.metrics;
    dom.kpiTotal.textContent = Number(m.total_events || 0).toLocaleString();
    dom.kpiUnique.textContent = Number(m.unique_ips || 0).toLocaleString();
    dom.kpiCritical.textContent = Number(m.critical_breaches || 0).toLocaleString();
    dom.kpiEntropy.textContent = Number(m.avg_entropy || 0).toFixed(2) + " b/B";
    renderSidePanels();
  }

  function renderSidePanels() {
    const m = state.metrics;
    const total = Math.max(m.total_events || 1, 1);

    // Top Origins
    const countries = m.top_countries || [];
    if (countries.length === 0) {
      dom.topOriginsList.innerHTML = `<div class="text-xs text-slate-500 py-2">Awaiting incoming telemetry...</div>`;
    } else {
      dom.topOriginsList.innerHTML = countries
        .map((c) => {
          const pct = Math.min(100, Math.round((c.cnt / total) * 100));
          return `
            <div class="space-y-1">
              <div class="flex items-center justify-between text-xs">
                <span class="text-slate-200 font-medium flex items-center gap-1.5">
                  <span class="font-mono-code text-[11px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">${escapeHtml(c.iso_code)}</span>
                  ${escapeHtml(c.country)}
                </span>
                <span class="font-mono-code text-slate-400">${c.cnt} <span class="text-slate-600">(${pct}%)</span></span>
              </div>
              <div class="w-full h-1.5 bg-slate-900 rounded-full overflow-hidden">
                <div class="h-full bg-orange-500/80 rounded-full" style="width: ${pct}%"></div>
              </div>
            </div>
          `;
        })
        .join("");
    }

    // Protocol Split
    const protocols = m.protocols || {};
    const entries = Object.entries(protocols);
    if (entries.length === 0) {
      dom.protocolSplitContainer.innerHTML = `<div class="text-xs text-slate-500 py-2">No protocol telemetry recorded.</div>`;
    } else {
      dom.protocolSplitContainer.innerHTML = entries
        .map(([proto, count]) => {
          const pct = Math.min(100, Math.round((count / total) * 100));
          const barColor = proto.includes("SSH") ? "bg-amber-500/80" : "bg-red-500/80";
          return `
            <div class="space-y-1">
              <div class="flex items-center justify-between text-xs">
                <span class="font-mono-code text-slate-300">${escapeHtml(proto)}</span>
                <span class="font-mono-code text-slate-400">${count} (${pct}%)</span>
              </div>
              <div class="w-full h-1.5 bg-slate-900 rounded-full overflow-hidden">
                <div class="h-full ${barColor} rounded-full" style="width: ${pct}%"></div>
              </div>
            </div>
          `;
        })
        .join("");
    }
  }

  // ---------------------------------------------------------------------------
  // 4. Real-Time Forensic Table & Filtering
  // ---------------------------------------------------------------------------
  function getFilteredEvents() {
    const search = state.filters.search.trim().toLowerCase();
    const sev = state.filters.severity.toLowerCase();
    const proto = state.filters.protocol.toLowerCase();

    return state.events.filter((ev) => {
      if (sev !== "all" && (ev.severity || "").toLowerCase() !== sev) {
        return false;
      }
      if (proto !== "all" && !(ev.targeted_protocol || "").toLowerCase().includes(proto)) {
        return false;
      }
      if (search) {
        const hay = `${ev.source_ip} ${ev.reverse_ptr} ${ev.country} ${ev.iso_code} ${ev.attack_method} ${ev.credentials} ${ev.payload}`.toLowerCase();
        if (!hay.includes(search)) {
          return false;
        }
      }
      return true;
    });
  }

  function severityBadgeHtml(severity) {
    const dict = I18N[state.lang];
    const label = (dict.severityMap && dict.severityMap[severity]) || severity.toUpperCase();
    if (severity === "Critical") {
      return `<span class="badge-critical px-2 py-0.5 text-[11px] font-mono-code font-semibold rounded inline-flex items-center gap-1">
        <span class="h-1.5 w-1.5 rounded-full bg-red-500"></span>${escapeHtml(label)}
      </span>`;
    }
    if (severity === "Medium") {
      return `<span class="badge-medium px-2 py-0.5 text-[11px] font-mono-code font-semibold rounded inline-flex items-center gap-1">
        <span class="h-1.5 w-1.5 rounded-full bg-amber-400"></span>${escapeHtml(label)}
      </span>`;
    }
    return `<span class="badge-low px-2 py-0.5 text-[11px] font-mono-code font-semibold rounded inline-flex items-center gap-1">
      <span class="h-1.5 w-1.5 rounded-full bg-slate-400"></span>${escapeHtml(label)}
    </span>`;
  }

  function formatTimestamp(isoStr) {
    if (!isoStr) return "-";
    return isoStr.replace("T", " ").replace("Z", " UTC");
  }

  function renderForensicTable(flashFirstRow = false) {
    const filtered = getFilteredEvents();
    dom.eventCounterBadge.textContent = `${filtered.length} rows`;

    if (filtered.length === 0) {
      const emptyMsg = I18N[state.lang].emptyTableText;
      dom.tableBody.innerHTML = `
        <tr>
          <td colspan="7" class="px-4 py-10 text-center text-xs text-slate-500 font-mono-code">
            ${escapeHtml(emptyMsg)}
          </td>
        </tr>
      `;
      return;
    }

    dom.tableBody.innerHTML = filtered
      .slice(0, 120)
      .map((ev, idx) => {
        const rowFlashClass = flashFirstRow && idx === 0 ? "row-new-flash" : "";
        return `
          <tr class="forensic-row border-b border-slate-800/80 text-xs ${rowFlashClass}">
            <td class="px-3.5 py-2.5 whitespace-nowrap font-mono-code text-slate-400 text-[11px]">
              ${escapeHtml(formatTimestamp(ev.timestamp))}
            </td>
            <td class="px-3.5 py-2.5 whitespace-nowrap">
              <div class="font-mono-code font-medium text-slate-100">${escapeHtml(ev.source_ip)}</div>
              <div class="font-mono-code text-[11px] text-slate-500 truncate max-w-[190px]" title="${escapeHtml(ev.reverse_ptr)}">
                ${escapeHtml(ev.reverse_ptr)}
              </div>
            </td>
            <td class="px-3.5 py-2.5 whitespace-nowrap">
              <div class="flex items-center gap-1.5">
                <span class="font-mono-code text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                  ${escapeHtml(ev.iso_code)}
                </span>
                <span class="text-slate-200 font-medium">${escapeHtml(ev.country)}</span>
              </div>
              <div class="text-[11px] text-slate-500 truncate max-w-[160px]">${escapeHtml(ev.city)} · ${escapeHtml(ev.asn)}</div>
            </td>
            <td class="px-3.5 py-2.5 whitespace-nowrap">
              <span class="protocol-pill px-2 py-0.5 rounded font-mono-code text-[11px]">${escapeHtml(ev.targeted_protocol)}</span>
              <div class="text-[11px] text-slate-400 mt-0.5 font-medium">${escapeHtml(ev.attack_method)}</div>
            </td>
            <td class="px-3.5 py-2.5">
              <div class="font-mono-code text-[11px] text-amber-300/90 truncate max-w-[330px]" title="${escapeHtml(ev.credentials)}">
                <span class="text-slate-500">Auth:</span> ${escapeHtml(ev.credentials)}
              </div>
              <div class="font-mono-code text-[11px] text-slate-300 truncate max-w-[330px] mt-0.5" title="${escapeHtml(ev.payload)}">
                <span class="text-slate-500">Payload:</span> ${escapeHtml(ev.payload)}
              </div>
            </td>
            <td class="px-3.5 py-2.5 whitespace-nowrap font-mono-code text-right text-slate-300">
              ${Number(ev.entropy || 0).toFixed(2)}
            </td>
            <td class="px-3.5 py-2.5 whitespace-nowrap text-right">
              ${severityBadgeHtml(ev.severity)}
            </td>
          </tr>
        `;
      })
      .join("");
  }

  // ---------------------------------------------------------------------------
  // 5. Monochromatic Equirectangular World Threat Map (HTML5 Canvas)
  // ---------------------------------------------------------------------------
  function lonLatToXY(lon, lat, width, height) {
    const x = ((lon + 180) / 360) * width;
    const y = ((90 - lat) / 180) * height;
    return [x, y];
  }

  function resizeCanvas() {
    if (!dom.mapCanvas) return;
    const rect = dom.mapCanvas.parentElement.getBoundingClientRect();
    const dpr = window.devicePixelRatio || 1;
    dom.mapCanvas.width = rect.width * dpr;
    dom.mapCanvas.height = rect.height * dpr;
  }

  function drawWorldMap() {
    if (!dom.mapCanvas) return;
    const ctx = dom.mapCanvas.getContext("2d");
    const dpr = window.devicePixelRatio || 1;
    const width = dom.mapCanvas.width;
    const height = dom.mapCanvas.height;

    ctx.save();
    ctx.clearRect(0, 0, width, height);

    // 1. Subtle Latitude / Longitude Graticule Grid
    ctx.strokeStyle = "rgba(30, 41, 59, 0.55)";
    ctx.lineWidth = 1 * dpr;

    for (let lon = -150; lon <= 150; lon += 30) {
      const [x] = lonLatToXY(lon, 0, width, height);
      ctx.beginPath();
      ctx.moveTo(x, 0);
      ctx.lineTo(x, height);
      ctx.stroke();
    }
    for (let lat = -60; lat <= 60; lat += 30) {
      const [, y] = lonLatToXY(0, lat, width, height);
      ctx.beginPath();
      ctx.moveTo(0, y);
      ctx.lineTo(width, y);
      ctx.stroke();
    }

    // Equator & Prime Meridian subtle emphasis
    ctx.strokeStyle = "rgba(51, 65, 85, 0.65)";
    const [pmX, eqY] = lonLatToXY(0, 0, width, height);
    ctx.beginPath();
    ctx.moveTo(0, eqY);
    ctx.lineTo(width, eqY);
    ctx.moveTo(pmX, 0);
    ctx.lineTo(pmX, height);
    ctx.stroke();

    // 2. Monochromatic Continental Landmasses
    ctx.fillStyle = "#131c2e";
    ctx.strokeStyle = "#26354d";
    ctx.lineWidth = 1.1 * dpr;

    WORLD_LANDMASS_POLYGONS.forEach((poly) => {
      if (!poly.length) return;
      ctx.beginPath();
      poly.forEach(([lon, lat], i) => {
        const [x, y] = lonLatToXY(lon, lat, width, height);
        if (i === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
      });
      ctx.closePath();
      ctx.fill();
      ctx.stroke();
    });

    // 3. Draw Sensor Collector Node (SOC Home)
    const [homeX, homeY] = lonLatToXY(SENSOR_HOME.lon, SENSOR_HOME.lat, width, height);

    // Subtle great-circle trajectory arcs for recent incidents
    const recentSlice = state.events.slice(0, 28);
    recentSlice.forEach((ev, idx) => {
      if (typeof ev.latitude !== "number" || typeof ev.longitude !== "number") return;
      const [srcX, srcY] = lonLatToXY(ev.longitude, ev.latitude, width, height);
      const alpha = Math.max(0.06, 0.34 - idx * 0.01);

      ctx.strokeStyle =
        ev.severity === "Critical"
          ? `rgba(239, 68, 68, ${alpha})`
          : ev.severity === "Medium"
          ? `rgba(249, 115, 22, ${alpha})`
          : `rgba(148, 163, 184, ${alpha})`;
      ctx.lineWidth = 1.1 * dpr;

      const midX = (srcX + homeX) / 2;
      const midY = Math.min(srcY, homeY) - 28 * dpr;
      ctx.beginPath();
      ctx.moveTo(srcX, srcY);
      ctx.quadraticCurveTo(midX, midY, homeX, homeY);
      ctx.stroke();
    });

    // 4. Plot Incident Coordinate Markers
    const seenCoords = new Map();
    state.events.slice(0, 80).forEach((ev) => {
      const key = `${ev.latitude.toFixed(2)},${ev.longitude.toFixed(2)}`;
      if (!seenCoords.has(key)) {
        seenCoords.set(key, { ev, count: 1 });
      } else {
        seenCoords.get(key).count += 1;
      }
    });

    seenCoords.forEach(({ ev, count }) => {
      const [x, y] = lonLatToXY(ev.longitude, ev.latitude, width, height);
      const baseRadius = Math.min(7.5, 3.5 + Math.log2(count + 1)) * dpr;

      let fillColor = "#94a3b8";
      let ringColor = "rgba(148, 163, 184, 0.25)";
      if (ev.severity === "Critical") {
        fillColor = "#ef4444";
        ringColor = "rgba(239, 68, 68, 0.28)";
      } else if (ev.severity === "Medium") {
        fillColor = "#f97316";
        ringColor = "rgba(249, 115, 22, 0.26)";
      }

      // Outer tactical halo
      ctx.beginPath();
      ctx.arc(x, y, baseRadius * 2.1, 0, Math.PI * 2);
      ctx.fillStyle = ringColor;
      ctx.fill();

      // Core precision point
      ctx.beginPath();
      ctx.arc(x, y, baseRadius, 0, Math.PI * 2);
      ctx.fillStyle = fillColor;
      ctx.fill();
      ctx.lineWidth = 1 * dpr;
      ctx.strokeStyle = "#09090b";
      ctx.stroke();
    });

    // 5. Active Ripple Animations for Live Incoming Packets
    const now = performance.now();
    state.pulseAnimations = state.pulseAnimations.filter((p) => now - p.bornAt < 1800);
    state.pulseAnimations.forEach((p) => {
      const progress = (now - p.bornAt) / 1800;
      const [x, y] = lonLatToXY(p.lon, p.lat, width, height);
      const radius = (4 + progress * 22) * dpr;
      const alpha = (1 - progress) * 0.75;

      ctx.beginPath();
      ctx.arc(x, y, radius, 0, Math.PI * 2);
      ctx.strokeStyle =
        p.severity === "Critical"
          ? `rgba(239, 68, 68, ${alpha})`
          : `rgba(249, 115, 22, ${alpha})`;
      ctx.lineWidth = 1.6 * dpr;
      ctx.stroke();
    });

    // 6. Collector Home Node Marker
    ctx.beginPath();
    ctx.arc(homeX, homeY, 5.5 * dpr, 0, Math.PI * 2);
    ctx.fillStyle = "#10b981";
    ctx.fill();
    ctx.lineWidth = 1.5 * dpr;
    ctx.strokeStyle = "#052e16";
    ctx.stroke();

    ctx.restore();

    if (state.pulseAnimations.length > 0) {
      requestAnimationFrame(drawWorldMap);
    }
  }

  function handleCanvasHover(evt) {
    if (!dom.mapCanvas) return;
    const rect = dom.mapCanvas.getBoundingClientRect();
    const mouseX = evt.clientX - rect.left;
    const mouseY = evt.clientY - rect.top;

    let closest = null;
    let minDist = 14;

    state.events.slice(0, 80).forEach((ev) => {
      const [x, y] = lonLatToXY(ev.longitude, ev.latitude, rect.width, rect.height);
      const dist = Math.hypot(mouseX - x, mouseY - y);
      if (dist < minDist) {
        minDist = dist;
        closest = { ev, x, y };
      }
    });

    if (closest) {
      const { ev, x, y } = closest;
      dom.mapTooltip.classList.remove("hidden");
      dom.mapTooltip.style.left = `${Math.min(rect.width - 230, Math.max(12, x + 14))}px`;
      dom.mapTooltip.style.top = `${Math.min(rect.height - 95, Math.max(12, y - 20))}px`;
      dom.mapTooltip.innerHTML = `
        <div class="font-mono-code text-[11px] font-semibold text-slate-100">${escapeHtml(ev.source_ip)} (${escapeHtml(ev.iso_code)})</div>
        <div class="text-[11px] text-slate-300">${escapeHtml(ev.city)}, ${escapeHtml(ev.country)}</div>
        <div class="text-[10px] font-mono-code text-orange-400 mt-0.5">${escapeHtml(ev.attack_method)}</div>
        <div class="text-[10px] font-mono-code text-slate-400">Coord: ${ev.latitude.toFixed(2)}, ${ev.longitude.toFixed(2)}</div>
      `;
    } else {
      dom.mapTooltip.classList.add("hidden");
    }
  }

  // ---------------------------------------------------------------------------
  // 6. Data Fetching, WebSocket Telemetry & Actions
  // ---------------------------------------------------------------------------
  async function fetchInitialTelemetry() {
    try {
      const res = await fetch("/api/v1/telemetry?limit=120");
      if (!res.ok) return;
      const data = await res.json();
      state.status = data.status || "live";
      state.uptimeSeconds = data.uptime_seconds || 0;
      state.metrics = data.metrics || state.metrics;
      state.events = data.events || [];
      updateStatusIndicator();
      dom.uptimeValue.textContent = formatUptime(state.uptimeSeconds);
      renderMetrics();
      renderForensicTable(false);
      drawWorldMap();
    } catch (err) {
      console.error("Telemetry fetch error:", err);
    }
  }

  function connectWebSocket() {
    const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
    const wsUrl = `${proto}//${window.location.host}/ws/telemetry`;
    const ws = new WebSocket(wsUrl);

    ws.onopen = () => {
      state.status = "live";
      updateStatusIndicator();
    };

    ws.onmessage = (msgEvent) => {
      try {
        const packet = JSON.parse(msgEvent.data);
        if (packet.type === "initial_snapshot") {
          state.status = packet.status || "live";
          state.uptimeSeconds = packet.uptime_seconds || state.uptimeSeconds;
          state.metrics = packet.metrics || state.metrics;
          state.events = packet.events || [];
          renderMetrics();
          renderForensicTable(false);
          drawWorldMap();
        } else if (packet.type === "telemetry_event" && packet.event) {
          const ev = packet.event;
          state.events.unshift(ev);
          if (state.events.length > 250) {
            state.events.pop();
          }
          state.metrics = packet.metrics || state.metrics;
          state.uptimeSeconds = packet.uptime_seconds || state.uptimeSeconds;

          // Trigger map ripple animation
          state.pulseAnimations.push({
            lat: ev.latitude,
            lon: ev.longitude,
            severity: ev.severity,
            bornAt: performance.now()
          });

          renderMetrics();
          renderForensicTable(true);
          drawWorldMap();
        } else if (packet.type === "database_cleared") {
          state.events = [];
          state.metrics = packet.metrics || state.metrics;
          renderMetrics();
          renderForensicTable(false);
          drawWorldMap();
        } else if (packet.type === "heartbeat") {
          state.status = packet.status || "live";
          state.uptimeSeconds = packet.uptime_seconds || state.uptimeSeconds;
          updateStatusIndicator();
        }
      } catch (e) {
        console.error("WS parse error:", e);
      }
    };

    ws.onclose = () => {
      state.status = "idle";
      updateStatusIndicator();
      setTimeout(connectWebSocket, 3000);
    };
  }

  function showToast(message) {
    if (!dom.toastContainer || !dom.toastMessage) return;
    dom.toastMessage.textContent = message;
    dom.toastContainer.classList.remove("hidden");
    setTimeout(() => {
      dom.toastContainer.classList.add("hidden");
    }, 3200);
  }

  function escapeHtml(str) {
    if (str === null || str === undefined) return "";
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  function bindEvents() {
    dom.langBtnEn.addEventListener("click", () => setLanguage("en"));
    dom.langBtnId.addEventListener("click", () => setLanguage("id"));

    dom.searchInput.addEventListener("input", (e) => {
      state.filters.search = e.target.value;
      renderForensicTable(false);
    });

    dom.severitySelect.addEventListener("change", (e) => {
      state.filters.severity = e.target.value;
      renderForensicTable(false);
    });

    dom.protocolSelect.addEventListener("change", (e) => {
      state.filters.protocol = e.target.value;
      renderForensicTable(false);
    });

    dom.btnExportJson.addEventListener("click", () => {
      window.location.href = "/api/v1/export/json";
    });

    dom.btnExportCsv.addEventListener("click", () => {
      window.location.href = "/api/v1/export/csv";
    });

    dom.btnSimulateBurst.addEventListener("click", async () => {
      dom.btnSimulateBurst.disabled = true;
      try {
        await fetch("/api/v1/simulate-burst?count=5", { method: "POST" });
        showToast(I18N[state.lang].toastBurst);
      } finally {
        dom.btnSimulateBurst.disabled = false;
      }
    });

    dom.btnClearDb.addEventListener("click", async () => {
      const dict = I18N[state.lang];
      if (!window.confirm(dict.confirmClearText)) return;
      const res = await fetch("/api/v1/database", { method: "DELETE" });
      if (res.ok) {
        state.events = [];
        await fetchInitialTelemetry();
        showToast(dict.toastCleared);
      }
    });

    window.addEventListener("resize", () => {
      resizeCanvas();
      drawWorldMap();
    });

    dom.mapCanvas.addEventListener("mousemove", handleCanvasHover);
    dom.mapCanvas.addEventListener("mouseleave", () => {
      dom.mapTooltip.classList.add("hidden");
    });

    // Local 1-second uptime ticker
    setInterval(() => {
      state.uptimeSeconds += 1;
      dom.uptimeValue.textContent = formatUptime(state.uptimeSeconds);
    }, 1000);
  }

  document.addEventListener("DOMContentLoaded", () => {
    cacheDom();
    resizeCanvas();
    bindEvents();
    setLanguage(state.lang);
    fetchInitialTelemetry();
    connectWebSocket();
  });
})();
