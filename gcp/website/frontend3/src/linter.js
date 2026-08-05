import "./linter.scss";
import "@github/clipboard-copy-element";



document.addEventListener("DOMContentLoaded", function () {
  let currentSourceIssues = [];
  let filteredIssues = [];
  let findingDetails = {};
  let activeVulnData = {};
  let activeVulnValueMaps = {};
  const issuesPerPage = 15;
  let currentPage = 1;
  let sortDirection = "desc";
  let dataLoadingComplete = false;

  const globalLoader = document.getElementById("global-loader");
  const searchInput = document.getElementById("search-input");
  const modifiedHeader = document.getElementById("modified-header");
  const tabBarContainer = document.querySelector(".tab-bar-container");
  const tabSwitch = document.getElementById("tab-switch");
  const tabsContent = document.getElementById("tabs-content");

  const homeDbFilter = document.getElementById("homedb-filter");
  const homeDbFilterSelected = document.getElementById(
    "homedb-filter-selected"
  );
  const homeDbFilterOptions = document.getElementById(
    "homedb-filter-options"
  );

  const findingsFilter = document.getElementById("findings-filter");
  const findingsFilterSelected = document.getElementById(
    "findings-filter-selected"
  );
  const findingsFilterOptions = document.getElementById(
    "findings-filter-options"
  );

  let selectedDb = "";
  let selectedFinding = "";
  let sourceNames = [];
  let prefixToSource = {};
  let summaryData = null;

  // Cache for source findings: sourceName -> Array<Issue>
  const sourceFindingsCache = new Map();
  // In-flight fetch promises: sourceName -> Promise<Array<Issue>>
  const inFlightFindingsFetches = new Map();

  function applyFiltersFromURL() {
    const params = new URLSearchParams(window.location.search);
    const db = params.get("homedb");
    if (db) {
      selectedDb = db;
    }
  }

  function updateURL(db, replace = false) {
    const params = new URLSearchParams(window.location.search);
    if (db) {
      params.set("homedb", db);
    } else {
      params.delete("homedb");
    }
    const newURL = `${
      window.location.pathname
    }?${params.toString()}`.replace(/\?$/, "");

    if (replace) {
      history.replaceState({ path: newURL }, "", newURL);
    } else {
      history.pushState({ path: newURL }, "", newURL);
    }
  }

  applyFiltersFromURL();

  // Cache of source names to detailed linter results Promise.
  const fetchedLinterSources = new Map();

  /**
   * Lazily fetches and caches detailed GCS linter findings for a given source on demand.
   * Uses in-flight promise deduplication to prevent duplicate concurrent fetches.
   * @param {string} sourceName - The ecosystem source name (e.g. "ghsa").
   * @returns {Promise<void>}
   */
  async function ensureLinterFindingsForSource(sourceName) {
    if (!sourceName) return;
    if (fetchedLinterSources.has(sourceName)) {
      return fetchedLinterSources.get(sourceName);
    }

    const fetchPromise = (async () => {
      try {
        const res = await fetch(`/linter-findings/${sourceName}`);
        if (res.ok) {
          const data = await res.json();
          for (const path in data) {
            const bugId = path.split("/").pop().replace(".json", "");
            if (!findingDetails[bugId]) findingDetails[bugId] = [];
            findingDetails[bugId].push(...data[path]);
          }
        }
      } catch (e) {
        console.warn(`Failed to fetch linter source: ${sourceName}`, e);
        // Allow retrying on subsequent clicks if network request failed
        fetchedLinterSources.delete(sourceName);
      }
    })();

    fetchedLinterSources.set(sourceName, fetchPromise);
    return fetchPromise;
  }

  /**
   * Fetches findings for a single source, using memory cache and in-flight deduplication.
   * @param {string} sourceName
   * @returns {Promise<Array<Object>>}
   */
  async function fetchSourceFindings(sourceName) {
    if (!sourceName) return [];
    if (sourceFindingsCache.has(sourceName)) {
      return sourceFindingsCache.get(sourceName);
    }
    if (inFlightFindingsFetches.has(sourceName)) {
      return inFlightFindingsFetches.get(sourceName);
    }

    const fetchPromise = (async () => {
      try {
        const url = `https://api.test.osv.dev/v1experimental/importfindings/${sourceName}`;
        const res = await fetch(url);
        const data = res.ok ? await res.json() : { invalid_records: [] };
        const records = data.invalid_records || [];
        sourceFindingsCache.set(sourceName, records);
        return records;
      } catch (err) {
        console.warn(`Failed to fetch findings for source ${sourceName}:`, err);
        return [];
      } finally {
        inFlightFindingsFetches.delete(sourceName);
      }
    })();

    inFlightFindingsFetches.set(sourceName, fetchPromise);
    return fetchPromise;
  }

  /**
   * Sets the active source, updates URL, loads data on-demand, and re-filters.
   * @param {string} sourceName
   */
  async function selectSource(sourceName) {
    if (!sourceName) return;
    if (selectedDb === sourceName && currentSourceIssues.length > 0) {
      return;
    }
    selectedDb = sourceName;
    updateURL(selectedDb);
    updateFilterSelectedLabels();

    dataLoadingComplete = false;
    displayIssues(); // Show "Loading data..."

    currentSourceIssues = await fetchSourceFindings(selectedDb);
    dataLoadingComplete = true;
    updateFilterSelectedLabels();
    applyFilters();
  }

  function updateFilterSelectedLabels() {
    const hasSourceCounts = Boolean(summaryData?.sources && Object.keys(summaryData.sources).length > 0);
    if (selectedDb) {
      if (hasSourceCounts && summaryData.sources[selectedDb] !== undefined) {
        const count = summaryData.sources[selectedDb];
        homeDbFilterSelected.textContent = `${selectedDb} (${count} issues)`;
      } else if (currentSourceIssues.length > 0) {
        homeDbFilterSelected.textContent = `${selectedDb} (${currentSourceIssues.length} issues)`;
      } else {
        homeDbFilterSelected.textContent = selectedDb;
      }
    } else {
      homeDbFilterSelected.textContent = "Select Database";
    }

    if (selectedFinding) {
      const name = selectedFinding.replace("IMPORT_FINDING_TYPE_", "");
      const count = summaryData?.findings?.[selectedFinding];
      findingsFilterSelected.textContent = count !== undefined ? `${name} (${count} issues)` : name;
    } else {
      findingsFilterSelected.textContent = "All Findings";
    }
  }

  function renderFilterDropdowns() {
    const hasSourceCounts = Boolean(summaryData?.sources && Object.keys(summaryData.sources).length > 0);
    const hasFindingCounts = Boolean(summaryData?.findings && Object.keys(summaryData.findings).length > 0);

    // 1. Render Database Options
    homeDbFilterOptions.innerHTML = "";
    const sortedSources = [...sourceNames].sort();
    for (const dbName of sortedSources) {
      const option = document.createElement("div");
      option.className = "filter-option";
      option.dataset.value = dbName;
      if (hasSourceCounts && summaryData.sources[dbName] !== undefined) {
        const count = summaryData.sources[dbName];
        option.dataset.count = count;
        option.textContent = `${dbName} (${count})`;
      } else {
        option.textContent = dbName;
      }
      homeDbFilterOptions.appendChild(option);
    }

    // 2. Render Findings Options
    findingsFilterOptions.innerHTML = `<div class="filter-option" data-value="" data-name="All Findings">All Findings</div>`;
    const findingKeys = hasFindingCounts
      ? Object.keys(summaryData.findings).sort()
      : [
          "IMPORT_FINDING_TYPE_INVALID_JSON",
          "IMPORT_FINDING_TYPE_INVALID_PACKAGE",
          "IMPORT_FINDING_TYPE_INVALID_PURL",
          "IMPORT_FINDING_TYPE_INVALID_VERSION",
          "IMPORT_FINDING_TYPE_INVALID_COMMIT",
          "IMPORT_FINDING_TYPE_INVALID_RANGE",
          "IMPORT_FINDING_TYPE_INVALID_RECORD",
          "IMPORT_FINDING_TYPE_INVALID_ALIASES",
          "IMPORT_FINDING_TYPE_INVALID_UPSTREAM",
          "IMPORT_FINDING_TYPE_INVALID_RELATED",
          "IMPORT_FINDING_TYPE_BAD_ALIASED_CVE",
        ];

    for (const finding of findingKeys) {
      const name = finding.replace("IMPORT_FINDING_TYPE_", "");
      const option = document.createElement("div");
      option.className = "filter-option";
      option.dataset.value = finding;
      option.dataset.name = name;
      if (hasFindingCounts && summaryData.findings[finding] !== undefined) {
        const count = summaryData.findings[finding];
        option.dataset.count = count;
        option.textContent = `${name} (${count})`;
      } else {
        option.textContent = name;
      }
      findingsFilterOptions.appendChild(option);
    }

    updateFilterSelectedLabels();
  }

  async function loadData() {
    globalLoader.classList.add("visible");

    // 1. Load source list and summary in parallel
    const [sourceRes, summaryRes] = await Promise.allSettled([
      fetch(
        "https://raw.githubusercontent.com/google/osv.dev/master/source_test.yaml"
      ),
      fetch("/linter-findings/summary"),
    ]);

    if (sourceRes.status === "fulfilled" && sourceRes.value.ok) {
      try {
        const yamlText = await sourceRes.value.text();
        const sources = jsyaml.load(yamlText);
        sourceNames = sources.map((s) => s.name);
        sources.forEach((s) => {
          if (s.db_prefix && Array.isArray(s.db_prefix)) {
            s.db_prefix.forEach((p) => {
              prefixToSource[p.toUpperCase()] = s.name;
            });
          }
        });
      } catch (e) {
        console.warn("Failed to parse source_test.yaml", e);
      }
    }

    if (summaryRes.status === "fulfilled" && summaryRes.value.ok) {
      try {
        summaryData = await summaryRes.value.json();
        if (summaryData?.sources) {
          Object.keys(summaryData.sources).forEach((src) => {
            if (!sourceNames.includes(src)) sourceNames.push(src);
          });
        }
      } catch (e) {
        console.warn("Failed to parse summary.json", e);
      }
    }

    // 2. Determine initial selected database
    if (selectedDb && !sourceNames.includes(selectedDb)) {
      selectedDb = "";
      updateURL("", true);
    }

    if (!selectedDb) {
      if (summaryData?.sources) {
        const firstWithIssues = Object.keys(summaryData.sources).find(
          (s) => summaryData.sources[s] > 0
        );
        if (firstWithIssues) {
          selectedDb = firstWithIssues;
          updateURL(selectedDb, true);
        }
      }
    }

    renderFilterDropdowns();
    setupEventListeners();

    // 3. Load only the selected source's findings if a database is selected
    if (selectedDb) {
      currentSourceIssues = await fetchSourceFindings(selectedDb);
    } else {
      currentSourceIssues = [];
    }
    dataLoadingComplete = true;
    globalLoader.classList.remove("visible");
    updateFilterSelectedLabels();
    applyFilters();
  }

  function setupEventListeners() {
    searchInput.addEventListener("input", () => {
      const val = searchInput.value.trim().toUpperCase();
      // Check if search prefix matches a different database
      for (const [prefix, src] of Object.entries(prefixToSource)) {
        if (val.startsWith(prefix) && src !== selectedDb) {
          selectSource(src);
          return;
        }
      }
      applyFilters();
    });

    modifiedHeader.addEventListener("click", () => {
      sortDirection = sortDirection === "asc" ? "desc" : "asc";
      const icon = modifiedHeader.querySelector(".material-icons");
      icon.textContent =
        sortDirection === "asc" ? "expand_less" : "expand_more";
      applyFilters();
    });
    tabBarContainer.addEventListener("click", handleTabClick);

    tabSwitch.addEventListener("wheel", (e) => {
      if (e.deltaY !== 0) {
        e.preventDefault();
        tabSwitch.scrollLeft += e.deltaY;
      }
    });

    tabSwitch.addEventListener("scroll", () => {
      if (tabSwitch.scrollLeft > 0) {
        tabBarContainer.classList.add("scrolled");
      } else {
        tabBarContainer.classList.remove("scrolled");
      }
    });

    homeDbFilter.addEventListener("click", (e) => {
      e.stopPropagation();
      toggleFilter("homedb");
    });
    findingsFilter.addEventListener("click", (e) => {
      e.stopPropagation();
      toggleFilter("findings");
    });

    homeDbFilterOptions.addEventListener("click", (e) => {
      const option = e.target.closest(".filter-option");
      if (option) {
        const { value } = option.dataset;
        selectSource(value);
      }
    });

    findingsFilterOptions.addEventListener("click", (e) => {
      const option = e.target.closest(".filter-option");
      if (option) {
        const { value, name, count } = option.dataset;
        selectedFinding = value;
        findingsFilterSelected.textContent = count ? `${name} (${count} issues)` : (name || "All Findings");
        applyFilters();
      }
    });
  }

  function applyFilters() {
    const searchTerm = searchInput.value.trim().toLowerCase();

    filteredIssues = currentSourceIssues.filter((issue) => {
      const bugIdMatch = issue.bug_id.toLowerCase().includes(searchTerm);
      const findingMatch =
        !selectedFinding || issue.findings.includes(selectedFinding);
      return bugIdMatch && findingMatch;
    });

    currentPage = 1;
    sortIssues();
    displayIssues();
  }

  function sortIssues() {
    filteredIssues.sort((a, b) => {
      const dateA = new Date(a.last_attempt);
      const dateB = new Date(b.last_attempt);
      if (sortDirection === "asc") {
        return dateA - dateB;
      } else {
        return dateB - dateA;
      }
    });
  }

  function displayIssues() {
    const tableBody = document
      .getElementById("issues-table")
      .getElementsByTagName("tbody")[0];
    tableBody.innerHTML = "";

    if (!selectedDb) {
      tableBody.innerHTML =
        '<tr><td colspan="3">Select a database from the dropdown above to view linter findings.</td></tr>';
      setupPagination();
      return;
    }

    const startIndex = (currentPage - 1) * issuesPerPage;
    const endIndex = startIndex + issuesPerPage;
    const paginatedIssues = filteredIssues.slice(startIndex, endIndex);

    if (paginatedIssues.length === 0) {
      if (dataLoadingComplete) {
        tableBody.innerHTML = '<tr><td colspan="3">No issues found.</td></tr>';
      } else {
        tableBody.innerHTML =
          '<tr><td colspan="3">Loading data...</td></tr>';
      }
    } else {
      paginatedIssues.forEach((issue) => {
        let row = tableBody.insertRow();
        row.classList.add("clickable");
        row.addEventListener("click", () => {
          openCombinedView(issue.bug_id);
        });

        let cell1 = row.insertCell();
        let cell2 = row.insertCell();
        let cell3 = row.insertCell();

        const bugLink = document.createElement("a");
        bugLink.href = `https://api.test.osv.dev/v1/vulns/${issue.bug_id}`;
        bugLink.textContent = issue.bug_id;
        bugLink.addEventListener("click", (e) => {
          e.stopPropagation();
          openCombinedView(issue.bug_id);
          e.preventDefault();
        });
        cell1.appendChild(bugLink);

        const findingsContainer = document.createElement("div");
        issue.findings.forEach((finding) => {
          const findingSpan = document.createElement("span");
          findingSpan.textContent = finding.replace("IMPORT_FINDING_TYPE_", "");
          findingSpan.className = "finding-tag";
          findingsContainer.appendChild(findingSpan);
        });
        cell2.appendChild(findingsContainer);

        cell3.textContent = new Date(issue.last_attempt).toLocaleString();
      });
    }
    setupPagination();
  }

  function setupPagination() {
    const paginationControls = document.getElementById("pagination-controls");
    paginationControls.innerHTML = "";
    const pageCount = Math.ceil(filteredIssues.length / issuesPerPage);

    if (pageCount <= 1) return;

    const prevButton = document.createElement("button");
    prevButton.textContent = "Previous";
    prevButton.disabled = currentPage === 1;
    prevButton.addEventListener("click", () => {
      if (currentPage > 1) {
        currentPage--;
        displayIssues();
      }
    });
    paginationControls.appendChild(prevButton);

    const pageInfo = document.createElement("span");
    pageInfo.textContent = ` Page ${currentPage} of ${pageCount} `;
    pageInfo.style.margin = "0 10px";
    paginationControls.appendChild(pageInfo);

    const nextButton = document.createElement("button");
    nextButton.textContent = "Next";
    nextButton.disabled = currentPage === pageCount;
    nextButton.addEventListener("click", () => {
      if (currentPage < pageCount) {
        currentPage++;
        displayIssues();
      }
    });
    paginationControls.appendChild(nextButton);
  }

  /**
   * Sanitizes a vulnerability ID string by stripping special characters for safe DOM element ID usage.
   * @param {string} bugId - Raw vulnerability identifier.
   * @returns {string} Sanitized ID string.
   */
  function sanitiseBugId(bugId) {
    // Keep only alphanumeric characters, hyphens, and colons
    return bugId.replace(/[^a-zA-Z0-9-:]/g, "");
  }

  /**
   * Opens a detailed tab view split into Vulnerability JSON and Linter Findings columns.
   * Fetches full vulnerability record JSON from the API and renders the interactive JSON tree.
   * @param {string} bugId - Vulnerability identifier.
   */
  function openCombinedView(bugId) {
    const safeBugId = sanitiseBugId(bugId);

    const tabId = `details-${safeBugId}`;
    const existingTab = tabBarContainer.querySelector(`[data-tab="${tabId}"]`);
    if (existingTab) {
      setActiveTab(tabId);
      return;
    }

    const tabButton = document.createElement("div");
    tabButton.className = "tab-switch-button";
    tabButton.dataset.tab = tabId;

    const titleSpan = document.createElement("span");
    titleSpan.className = "tab-title";
    titleSpan.textContent = bugId;
    tabButton.appendChild(titleSpan);

    const closeButton = document.createElement("i");
    closeButton.className = "material-icons close-tab";
    closeButton.textContent = "close";
    closeButton.dataset.tabClose = tabId;
    tabButton.appendChild(closeButton);

    tabSwitch.appendChild(tabButton);

    const vulnJsonId = `vuln-json-${safeBugId}`;
    const findingsJsonId = `findings-json-${safeBugId}`;
    const copyButtonId = `copy-json-${safeBugId}`;

    const tabContent = document.createElement("div");
    tabContent.className = "tab-content";
    tabContent.id = tabId;

    tabContent.innerHTML = `
      <div class="details-grid">
          <div class="details-column">
              <div class="details-header">
                  <h2>Vulnerability Data</h2>
                  <clipboard-copy id="${copyButtonId}" class="copy-button" title="Copy raw JSON">
                      <i class="material-icons">content_copy</i>
                  </clipboard-copy>
              </div>
              <div id="${vulnJsonId}" class="json-container">Loading...</div>
          </div>
          <div class="details-column">
              <div class="details-header">
                  <h2>Linter Findings</h2>
              </div>
              <div id="${findingsJsonId}" class="json-pre">Loading...</div>
          </div>
      </div>
                `;



    tabsContent.appendChild(tabContent);
    setActiveTab(tabId);

    // Fetch vuln data with the original bugId
    fetch(`https://api.test.osv.dev/v1/vulns/${bugId}`)
      .then((res) =>
        res.ok ? res.json() : { error: `Failed to load: ${res.status}` }
      )
      .then((data) => {
        const container = document.getElementById(vulnJsonId);
        container.textContent = ''; // Clear "Loading..."
        if (data.error) {
          container.textContent = data.error;
          return;
        }
        activeVulnData[bugId] = data;

        const copyButton = document.getElementById(copyButtonId);
        if (copyButton) {
          const jsonStr = JSON.stringify(data, null, 2);
          copyButton.value = jsonStr;
          copyButton.setAttribute('value', jsonStr);
          copyButton.addEventListener('clipboard-copy', () => {
            const icon = copyButton.querySelector('.material-icons');
            if (icon) icon.textContent = 'check';
            setTimeout(() => {
              if (icon) icon.textContent = 'content_copy';
            }, 2000);
          });
        }

        const valueMap = {};
        activeVulnValueMaps[bugId] = valueMap;
        
        container.appendChild(renderCustomJSON(data, '', true, valueMap));

        // Use Event Delegation on the container for collapsible JSON nodes
        container.addEventListener('click', (e) => {
          const toggle = e.target.closest('.json-toggle');
          if (!toggle) return;
          e.stopPropagation();
          const isOpen = toggle.classList.toggle('open');
          setToggleState(toggle, isOpen);
          const children = toggle.nextElementSibling;
          if (children && children.classList.contains('json-children')) {
            children.style.display = isOpen ? 'block' : 'none';
          }
        });
      })
      .catch((err) => {
        document.getElementById(
          vulnJsonId
        ).textContent = `Error: ${err.message}`;
      });


    // Display finding data
    (async () => {
      const issue = currentSourceIssues.find((i) => i.bug_id === bugId);
      const source = issue?.source || selectedDb;
      if (source) {
        await ensureLinterFindingsForSource(source);
      }
      const details = findingDetails[bugId];
      const findingsEl = document.getElementById(findingsJsonId);
      if (details?.length) {
        findingsEl.textContent = ''; // Clear "Loading..."
        findingsEl.appendChild(formatFindings(details, bugId));
      } else if (issue?.findings?.length) {
        findingsEl.textContent = '';
        const fallbackDetails = issue.findings.map((f) => ({
          Code: f.replace('IMPORT_FINDING_TYPE_', ''),
          Message: `Vulnerability flagged with finding: ${f.replace('IMPORT_FINDING_TYPE_', '')}`,
        }));
        findingsEl.appendChild(formatFindings(fallbackDetails, bugId));
      } else {
        findingsEl.textContent =
            "No linter findings available for this vulnerability.";
      }
    })();
  }

  /**
   * Updates the visual open/collapsed state and label text of a JSON toggle element.
   * @param {HTMLElement} toggle - The toggle span element.
   * @param {boolean} isOpen - Whether the section is expanded.
   */
  function setToggleState(toggle, isOpen) {
    toggle.classList.toggle('open', isOpen);
    const isArray = toggle.dataset.isObject !== 'true';
    toggle.textContent = isOpen 
      ? (isArray ? '▼ [' : '▼ {') 
      : (isArray ? '▶ [...]' : '▶ {...}');
  }

  /**
   * Generates an HTML table displaying linter findings for a given vulnerability.
   * @param {Array<Object>} details - List of linter finding objects.
   * @param {string} bugId - The vulnerability identifier.
   * @returns {HTMLTableElement} The constructed findings table element.
   */
  function formatFindings(details, bugId) {
    const table = document.createElement('table');
    table.className = 'findings-table';

    const thead = table.createTHead();
    const headerRow = thead.insertRow();
    ['Code', 'Message', ''].forEach(headerText => {
      const th = document.createElement('th');
      th.textContent = headerText;
      headerRow.appendChild(th);
    });

    const tbody = table.createTBody();
    details.forEach((finding) => {
      const row = tbody.insertRow();
      row.className = 'clickable-finding-row';
      row.insertCell().textContent = finding.Code || '';
      row.insertCell().textContent = finding.Message || '';
      
      const actionCell = row.insertCell();
      actionCell.className = 'action-cell';
      actionCell.innerHTML = '<i class="material-icons">search</i>';

      row.addEventListener('click', () => {
        highlightFinding(bugId, finding);
      });
    });

    return table;
  }

  /**
   * Recursively searches an object for a target value and returns all dot-separated JSON paths leading to it.
   * @param {*} obj - The object or value to inspect.
   * @param {*} value - The target value to locate.
   * @param {string[]} [currentPath=[]] - Accumulated path segments.
   * @param {string[]} [results=[]] - Accumulated path string results.
   * @returns {string[]} Found path strings.
   */
  function findPathsForValue(obj, value, currentPath = [], results = []) {
    if (obj === value) {
      results.push(currentPath.join('.'));
      return results;
    }
    if (typeof obj === 'object' && obj !== null) {
      for (const key in obj) {
        findPathsForValue(obj[key], value, [...currentPath, key], results);
      }
    }
    return results;
  }

  /**
   * Compares two range objects to check if their type, repo, and events match.
   * @param {Object} r1 - First range object.
   * @param {Object} r2 - Second range object.
   * @returns {boolean} True if ranges match.
   */
  function isSameRange(r1, r2) {
    if (r1.type !== r2.type) return false;
    if (r1.repo !== r2.repo) return false;
    if (!r1.events || !r2.events) return r1.events === r2.events;
    if (r1.events.length !== r2.events.length) return false;
    return JSON.stringify(r1.events) === JSON.stringify(r2.events);
  }

  /**
   * Finds the path to a specific affected range within the vulnerability record.
   * @param {Object} vulnData - The vulnerability protocol buffer JSON data.
   * @param {Object} targetRange - Range object to find.
   * @returns {string|null} Path string if found, otherwise null.
   */
  function findRangePath(vulnData, targetRange) {
    if (!vulnData || !vulnData.affected) return null;
    for (let i = 0; i < vulnData.affected.length; i++) {
      const affected = vulnData.affected[i];
      if (!affected.ranges) continue;
      for (let j = 0; j < affected.ranges.length; j++) {
        if (isSameRange(affected.ranges[j], targetRange)) {
          return `affected.${i}.ranges.${j}`;
        }
      }
    }
    return null;
  }

  /**
   * Extracts JSON paths from a linter finding message.
   * Handles schema errors (SCH:xxx), quote/value matches (RNG:002), range types, and top-level properties (REC:xxx).
   * @param {Object} finding - Finding record with Code and Message properties.
   * @param {string} bugId - Vulnerability ID.
   * @returns {string[]} Array of target JSON path strings.
   */
  function extractPathsFromFinding(finding, bugId) {
    const paths = [];
    if (!finding || !finding.Message) return paths;

    const vulnData = activeVulnData[bugId];
    const valueMap = activeVulnValueMaps[bugId];

    // 1. Check for schema paths (SCH:xxx)
    const schemaPathRegex = /(?:^|\s)-\s*([a-zA-Z0-9_\.]+):/g;
    let match;
    while ((match = schemaPathRegex.exec(finding.Message)) !== null) {
      paths.push(match[1]);
    }

    // 2. Check for overlapping event values (RNG:002) or anything in quotes using O(1) indexed valueMap
    const quoteRegex = /"([^"]+)"/g;
    let quoteMatch;
    while ((quoteMatch = quoteRegex.exec(finding.Message)) !== null) {
      const value = quoteMatch[1];
      if (!value.startsWith('{')) {
        if (valueMap && valueMap[value]) {
          paths.push(...valueMap[value]);
        } else if (vulnData) {
          const valuePaths = findPathsForValue(vulnData, value);
          paths.push(...valuePaths);
        }
      }
    }

    // 3. Check for unexpected range type (RNG:002 case 2)
    const rngTypeRegex = /unexpected range type "[^"]+" for (\{[\s\S]*\})/;
    const rngTypeMatch = rngTypeRegex.exec(finding.Message);
    if (rngTypeMatch) {
      try {
        const targetRange = JSON.parse(rngTypeMatch[1]);
        const path = findRangePath(vulnData, targetRange);
        if (path) {
          paths.push(path);
        }
      } catch (e) {
        console.error("Failed to parse range JSON from finding", e);
      }
    }

    // 4. Check for invalid top-level properties (REC:xxx)
    const invalidPropRegex = /Invalid ([a-zA-Z0-9_]+):/i;
    const invalidPropMatch = invalidPropRegex.exec(finding.Message);
    if (invalidPropMatch) {
      paths.push(invalidPropMatch[1].toLowerCase());
    }

    return paths;
  }

  /**
   * Highlights target finding elements in the interactive JSON tree and auto-expands parent nodes.
   * @param {string} bugId - Vulnerability ID.
   * @param {Object} finding - Linter finding object to highlight.
   */
  function highlightFinding(bugId, finding) {
    const safeBugId = sanitiseBugId(bugId);
    const vulnJsonId = `vuln-json-${safeBugId}`;
    const container = document.getElementById(vulnJsonId);
    if (!container) return;

    // Clear previous highlights
    container.querySelectorAll('.json-highlighted').forEach(el => {
      el.classList.remove('json-highlighted');
    });

    const paths = extractPathsFromFinding(finding, bugId);
    let firstHighlighted = null;

    paths.forEach(path => {
      const row = container.querySelector(`[data-json-path="${path}"]`);
      if (row) {
        row.classList.add('json-highlighted');
        
        // Ensure all parent elements are expanded
        let parent = row.parentElement;
        while (parent && parent !== container) {
          if (parent.classList.contains('json-children')) {
            parent.style.display = 'block';
            const toggle = parent.previousElementSibling;
            if (toggle?.classList.contains('json-toggle')) {
              setToggleState(toggle, true);
            }
          }
          parent = parent.parentElement;
        }

        // Expand the highlighted row itself if it is collapsed
        const myChildren = row.querySelector(':scope > .custom-json-node > .json-children');
        if (myChildren) {
          myChildren.style.display = 'block';
          const myToggle = row.querySelector(':scope > .custom-json-node > .json-toggle');
          if (myToggle) {
            setToggleState(myToggle, true);
          }
        }

        if (!firstHighlighted) {
          firstHighlighted = row;
        }
      }
    });

    if (firstHighlighted) {
      firstHighlighted.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }
  }

  /**
   * Recursively builds an interactive HTML DOM tree for rendering JSON structures with data-json-path attributes.
   * 
   * @param {*} data - The primitive or object value to render.
   * @param {string} [path=''] - The dot-separated JSON path leading to this node.
   * @param {boolean} [isRoot=false] - Whether this node is the root container of the JSON tree.
   * @param {Object<string, string[]>} [valueMap=null] - Optional lookup map populated with value -> path[] for O(1) searches.
   * @returns {HTMLElement} The root div.custom-json-node container element.
   */
  function renderCustomJSON(data, path = '', isRoot = false, valueMap = null) {
    const container = document.createElement('div');
    container.className = 'custom-json-node';
    if (path !== '') container.dataset.jsonPath = path;

    if (data === null || typeof data !== 'object') {
      if (valueMap && path && (typeof data === 'string' || typeof data === 'number')) {
        const strVal = String(data);
        if (!valueMap[strVal]) valueMap[strVal] = [];
        valueMap[strVal].push(path);
      }
      const span = document.createElement('span');
      const type = data === null ? 'null' : typeof data;
      span.className = `json-value-${type}`;
      span.textContent = type === 'string' ? `"${data}"` : String(data);
      container.appendChild(span);
      return container;
    }

    const isArray = Array.isArray(data);
    const keys = Object.keys(data);
    const openChar = isArray ? '[' : '{';
    const closeChar = isArray ? ']' : '}';

    if (keys.length === 0) {
      const span = document.createElement('span');
      span.className = 'json-bracket';
      span.textContent = `${openChar}${closeChar}`;
      container.appendChild(span);
      return container;
    }

    const toggle = document.createElement('span');
    toggle.className = 'json-toggle open';
    toggle.dataset.isObject = (!isArray).toString();
    toggle.textContent = `▼ ${openChar}`;

    const children = document.createElement('div');
    children.className = 'json-children';

    keys.forEach(key => {
      const val = data[key];
      const childPath = path ? `${path}.${key}` : `${key}`;
      const row = document.createElement('div');
      row.className = 'json-row';
      row.dataset.jsonPath = childPath;

      const keySpan = document.createElement('span');
      keySpan.className = isArray ? 'json-key array-index' : 'json-key';
      keySpan.textContent = isArray ? `${key}:` : `"${key}": `;
      row.appendChild(keySpan);

      row.appendChild(renderCustomJSON(val, childPath, false, valueMap));
      children.appendChild(row);
    });

    if (isRoot) {
      container.appendChild(document.createTextNode(openChar));
    } else {
      container.appendChild(toggle);
    }
    container.appendChild(children);

    const closeSpan = document.createElement('span');
    closeSpan.className = 'json-bracket';
    closeSpan.textContent = closeChar;
    container.appendChild(closeSpan);

    return container;
  }

  function handleTabClick(e) {
    const tabButton = e.target.closest(".tab-switch-button");
    if (tabButton) {
      if (e.target.classList.contains("close-tab")) {
        e.stopPropagation();
        closeTab(e.target.dataset.tabClose);
      } else {
        setActiveTab(tabButton.dataset.tab);
      }
    }
  }

  function setActiveTab(tabId) {
    // Buttons
    Array.from(tabBarContainer.querySelectorAll(".tab-switch-button")).forEach(
      (btn) => {
        btn.classList.toggle("active", btn.dataset.tab === tabId);
      }
    );
    // Content
    Array.from(tabsContent.children).forEach((content) => {
      content.classList.toggle("active", content.id === tabId);
    });
  }

  function closeTab(tabId) {
    const tabButton = tabBarContainer.querySelector(`[data-tab="${tabId}"]`);
    const tabContent = document.getElementById(tabId);

    if (tabButton) tabButton.remove();
    if (tabContent) tabContent.remove();

    // Activate the main tab if the closed one was active
    if (tabButton && tabButton.classList.contains("active")) {
      setActiveTab("linter-report");
    }
  }

  function toggleFilter(filterName) {
    const options = document.getElementById(`${filterName}-filter-options`);
    const isVisible = options.style.display === "block";

    // Hide all filter options first
    document
      .querySelectorAll(".filter-option-container")
      .forEach((el) => (el.style.display = "none"));

    if (!isVisible) {
      options.style.display = "block";
    }
  }

  document.addEventListener("click", function (e) {
    if (!e.target.closest(".filter-container")) {
      document
        .querySelectorAll(".filter-option-container")
        .forEach((el) => (el.style.display = "none"));
    }
  });

  loadData();
});
