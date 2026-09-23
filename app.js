/**
 * Road to MIT - Application Logic
 * Implements strict mode, data sanitization, and defensive programming against XSS.
 */
'use strict';

// --- Firebase Integration ---
import { initializeApp } from 'https://www.gstatic.com/firebasejs/10.9.0/firebase-app.js';
import { getAuth, onAuthStateChanged, signInWithEmailAndPassword, createUserWithEmailAndPassword, GoogleAuthProvider, signInWithPopup, signOut } from 'https://www.gstatic.com/firebasejs/10.9.0/firebase-auth.js';
import { getFirestore, doc, setDoc, getDoc } from 'https://www.gstatic.com/firebasejs/10.9.0/firebase-firestore.js';
import { firebaseConfig } from './firebase-config.js';

const firebaseApp = initializeApp(firebaseConfig);
const auth = getAuth(firebaseApp);
const db = getFirestore(firebaseApp);
let currentUser = null;

// --- Daily Quotes Database ---
const dailyQuotes = [
  { "day": 1, "quote": "You have power over your mind, not outside events. Realize this, and you will find strength.", "author": "Marcus Aurelius" },
  { "day": 2, "quote": "He who fears death will never do anything worthy of a man who is alive.", "author": "Seneca" },
  { "day": 3, "quote": "The only limit to our realization of tomorrow is our doubts of today.", "author": "Franklin D. Roosevelt" }
  // Expand with full 365 JSON array items as needed
];

// --- Security & Sanitization Helpers (XSS Prevention & Defense) ---

/**
 * Escapes characters that are sensitive in HTML context to prevent DOM XSS.
 * @param {string|any} str 
 * @returns {string}
 */
function escapeHTML(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/**
 * Ensures IDs are safe alphanumeric strings (letters, numbers, hyphens, underscores).
 * Prevents attribute injection or script break-out.
 * @param {string|any} id 
 * @returns {string}
 */
function sanitizeId(id) {
  return String(id || '').replace(/[^a-zA-Z0-9_-]/g, '');
}

/**
 * Validates and sanitizes date strings in YYYY-MM-DD format.
 * @param {string} dateStr 
 * @returns {string}
 */
function sanitizeDate(dateStr) {
  const match = String(dateStr || '').match(/^\d{4}-\d{2}-\d{2}$/);
  return match ? match[0] : getYYYYMMDD(new Date());
}

// --- State Management ---
const STORAGE_KEY = 'vr-road-to-mit:v4';
let state = { dailyTasks: {}, weeklyGoals: {}, monthlyGoals: {}, lastUpdate: null };
let selectedDate = new Date();

// Helper: Format Date to YYYY-MM-DD local
function getYYYYMMDD(d) {
  const offset = d.getTimezoneOffset() * 60000;
  return new Date(d.getTime() - offset).toISOString().split('T')[0];
}

// Helper: Get ISO Week string (YYYY-Www)
function getWeekString(d) {
  const date = new Date(d.getTime());
  date.setHours(0, 0, 0, 0);
  date.setDate(date.getDate() + 3 - (date.getDay() + 6) % 7);
  const week1 = new Date(date.getFullYear(), 0, 4);
  const weekNumber = 1 + Math.round(((date.getTime() - week1.getTime()) / 86400000 - 3 + (week1.getDay() + 6) % 7) / 7);
  return `${date.getFullYear()}-W${weekNumber.toString().padStart(2, '0')}`;
}

// Helper: Format Date to YYYY-MM
function getYYYYMM(d) {
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}`;
}

// Helper: Get Day of the Year (1 - 365/366)
function getDayOfYear(date) {
  const start = new Date(date.getFullYear(), 0, 0);
  const diff = date - start + (start.getTimezoneOffset() - date.getTimezoneOffset()) * 60 * 1000;
  const oneDay = 1000 * 60 * 60 * 24;
  return Math.floor(diff / oneDay);
}

// Helper to ensure state structure is valid
function initStateDefaults() {
  if (!state.dailyTasks || typeof state.dailyTasks !== 'object') state.dailyTasks = {};
  if (!state.weeklyGoals || typeof state.weeklyGoals !== 'object') state.weeklyGoals = {};
  if (!state.monthlyGoals || typeof state.monthlyGoals !== 'object') state.monthlyGoals = {};
}

// Data is now loaded via Firebase onAuthStateChanged
initStateDefaults();

async function loadDataFromFirebase(uid) {
  try {
    const docRef = doc(db, 'users', uid);
    const docSnap = await getDoc(docRef);
    if (docSnap.exists()) {
      const data = docSnap.data();
      state = data.trackerData || { dailyTasks: {}, weeklyGoals: {}, monthlyGoals: {}, lastUpdate: null };
    } else {
      state = { dailyTasks: {}, weeklyGoals: {}, monthlyGoals: {}, lastUpdate: null };
    }
    initStateDefaults();
    renderView();
  } catch (err) {
    console.error("Failed to load data from Firestore:", err);
    showToast("Error loading data");
  }
}

async function saveData() {
  state.lastUpdate = new Date().toISOString();
  
  if (currentUser) {
    try {
      await setDoc(doc(db, 'users', currentUser.uid), { trackerData: state }, { merge: true });
      const time = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
      const saveMobile = document.getElementById('save-mobile');
      const saveDesktop = document.getElementById('save-desktop');
      if (saveMobile) saveMobile.textContent = `Auto-saved ${time}`;
      if (saveDesktop) saveDesktop.textContent = `Auto-saved ${time}`;
    } catch (err) {
      console.error("Failed to save data to Firestore:", err);
      showToast("Error saving data");
    }
  }
}

function showToast(msg) {
  const container = document.getElementById('toast-container');
  if (!container) return;
  const toast = document.createElement('div');
  toast.className = 'toast';
  toast.innerHTML = `<span>✓</span> ${escapeHTML(msg)}`;
  container.appendChild(toast);
  setTimeout(() => toast.remove(), 3500);
}

// --- Data Operations ---
function generateId() {
  return Math.random().toString(36).substr(2, 9);
}

function addDailyTask(e) {
  if (e && e.preventDefault) e.preventDefault();
  const input = document.getElementById('new-task-input');
  if (!input) return;
  const text = input.value.trim();
  if (!text) return;

  const dateStr = getYYYYMMDD(selectedDate);
  if (!state.dailyTasks[dateStr]) state.dailyTasks[dateStr] = [];

  state.dailyTasks[dateStr].push({ id: generateId(), text, done: false });
  input.value = '';
  saveData();
  renderView();
  showToast('Task added');
}

function toggleDailyTask(dateStr, id) {
  const safeDate = sanitizeDate(dateStr);
  const safeId = sanitizeId(id);
  const tasks = state.dailyTasks[safeDate];
  if (!tasks) return;
  const task = tasks.find(t => t.id === safeId);
  if (task) {
    task.done = !task.done;
    saveData();
    renderView();
  }
}

function deleteDailyTask(dateStr, id) {
  const safeDate = sanitizeDate(dateStr);
  const safeId = sanitizeId(id);
  if (!state.dailyTasks[safeDate]) return;
  state.dailyTasks[safeDate] = state.dailyTasks[safeDate].filter(t => t.id !== safeId);
  saveData();
  renderView();
  showToast('Task deleted');
}

function addMonthlyGoal(e) {
  if (e && e.preventDefault) e.preventDefault();
  const input = document.getElementById('new-monthly-input');
  const monthSelector = document.getElementById('month-selector');
  if (!input || !monthSelector) return;
  const monthInput = monthSelector.value;
  const text = input.value.trim();
  if (!text || !monthInput) return;

  if (!state.monthlyGoals[monthInput]) state.monthlyGoals[monthInput] = [];
  if (state.monthlyGoals[monthInput].length >= 3) {
    showToast('Maximum 3 monthly goals allowed');
    return;
  }

  state.monthlyGoals[monthInput].push({ id: generateId(), text, done: false });
  input.value = '';
  saveData();
  renderView();
  showToast('Monthly goal added');
}

function toggleMonthlyGoal(monthStr, id) {
  const safeId = sanitizeId(id);
  const goals = state.monthlyGoals[monthStr];
  if (!goals) return;
  const goal = goals.find(g => g.id === safeId);
  if (goal) {
    goal.done = !goal.done;
    saveData();
    renderView();
  }
}

function deleteMonthlyGoal(monthStr, id) {
  const safeId = sanitizeId(id);
  if (!state.monthlyGoals[monthStr]) return;
  state.monthlyGoals[monthStr] = state.monthlyGoals[monthStr].filter(g => g.id !== safeId);
  saveData();
  renderView();
  showToast('Monthly goal deleted');
}

function addWeeklyGoal(e) {
  if (e && e.preventDefault) e.preventDefault();
  const input = document.getElementById('new-goal-input');
  const weekSelector = document.getElementById('week-selector');
  if (!input || !weekSelector) return;
  const weekInput = weekSelector.value;
  const text = input.value.trim();
  if (!text || !weekInput) return;

  if (!state.weeklyGoals[weekInput]) state.weeklyGoals[weekInput] = [];
  state.weeklyGoals[weekInput].push({ id: generateId(), text, done: false });

  input.value = '';
  saveData();
  renderView();
  showToast('Weekly objective added');
}

function toggleWeeklyGoal(weekStr, id) {
  const safeId = sanitizeId(id);
  const goals = state.weeklyGoals[weekStr];
  if (!goals) return;
  const goal = goals.find(g => g.id === safeId);
  if (goal) {
    goal.done = !goal.done;
    saveData();
    renderView();
  }
}

function deleteWeeklyGoal(weekStr, id) {
  const safeId = sanitizeId(id);
  if (!state.weeklyGoals[weekStr]) return;
  state.weeklyGoals[weekStr] = state.weeklyGoals[weekStr].filter(g => g.id !== safeId);
  saveData();
  renderView();
  showToast('Weekly objective deleted');
}

function resetData() {
  if (confirm("Are you sure you want to delete ALL data? This action cannot be undone.")) {
    state = { dailyTasks: {}, weeklyGoals: {}, monthlyGoals: {}, lastUpdate: null };
    saveData();
    renderView();
    showToast("All data has been reset.");
  }
}

// --- Import / Export ---
function exportData() {
  const dataStr = JSON.stringify(state, null, 2);
  const blob = new Blob([dataStr], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `VR-RoadToMIT-Backup-${getYYYYMMDD(new Date())}.json`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
  showToast("Backup downloaded successfully");
}

function importData(e) {
  const file = e.target.files && e.target.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = function (event) {
    try {
      const importedState = JSON.parse(event.target.result);
      if (importedState && typeof importedState === 'object' && importedState.dailyTasks) {
        state = {
          dailyTasks: typeof importedState.dailyTasks === 'object' && importedState.dailyTasks !== null ? importedState.dailyTasks : {},
          weeklyGoals: typeof importedState.weeklyGoals === 'object' && importedState.weeklyGoals !== null ? importedState.weeklyGoals : {},
          monthlyGoals: typeof importedState.monthlyGoals === 'object' && importedState.monthlyGoals !== null ? importedState.monthlyGoals : {},
          lastUpdate: new Date().toISOString()
        };
        saveData();
        renderView();
        showToast("Data restored successfully");
      } else {
        showToast("Invalid backup file format");
      }
    } catch (err) {
      showToast("Error parsing file");
    }
  };
  reader.readAsText(file);
}

// --- Modal Functionality ---
function openMotivationModal() {
  const today = new Date();
  const currentDayOfYear = getDayOfYear(today);
  const currentMonthStr = getYYYYMM(today);

  let dailyQuote = dailyQuotes.find(q => q.day === currentDayOfYear) ||
    dailyQuotes[(currentDayOfYear % dailyQuotes.length) || 0] ||
    { quote: "Set your goals high, and don't stop till you get there.", author: "Bo Jackson" };

  const mGoals = state.monthlyGoals[currentMonthStr] || [];
  const topGoal = mGoals.length > 0 ? mGoals[0] : null;

  const quoteContainer = document.getElementById('modal-quote-container');
  if (quoteContainer) {
    quoteContainer.innerHTML = `
      <div class="quote-text" style="font-size: 1.35rem;">"${escapeHTML(dailyQuote.quote)}"</div>
      <div class="quote-author" style="margin-top: 1rem; text-align: right;">&mdash; ${escapeHTML(dailyQuote.author)}</div>
    `;
  }

  const priorityContainer = document.getElementById('modal-priority-container');
  if (priorityContainer) {
    priorityContainer.innerHTML = `
      <h3 class="card-title" style="font-size: 1rem; color: var(--warning); display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.75rem;">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"></polygon></svg>
        Month's Primary Priority
      </h3>
      <p style="font-size: 1.15rem; font-weight: 600; color: var(--text-primary); ${topGoal && topGoal.done ? 'text-decoration: line-through; opacity: 0.6;' : ''}">
        ${topGoal ? escapeHTML(topGoal.text) : '<em>No primary goal set for this month. Set one in the Milestones tab!</em>'}
      </p>
    `;
  }

  const modal = document.getElementById('motivation-modal');
  if (modal) modal.classList.add('active');
}

function closeMotivationModal() {
  const modal = document.getElementById('motivation-modal');
  if (modal) modal.classList.remove('active');
}

function handleModalOverlayClick(e) {
  if (e.target.id === 'motivation-modal') {
    closeMotivationModal();
  }
}

document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') closeMotivationModal();
});

// --- Dashboard Renderers ---
function renderHeatmap() {
  const today = new Date();
  const yearAgo = new Date(today);
  yearAgo.setDate(today.getDate() - 364);

  const startDayOffset = yearAgo.getDay();
  const totalCells = 365 + startDayOffset;

  let cellsHTML = '';
  let currentMonth = -1;
  let col = 1;

  for (let i = 0; i < totalCells; i++) {
    const dayOfWeek = i % 7;
    if (dayOfWeek === 0 && i > 0) col++;

    if (i < startDayOffset) continue;

    const d = new Date(yearAgo);
    d.setDate(yearAgo.getDate() + (i - startDayOffset));
    const dateStr = getYYYYMMDD(d);

    if (d.getDate() === 1 || currentMonth === -1) {
      if (d.getMonth() !== currentMonth) {
        cellsHTML += `<div class="month-label" style="grid-row: 1; grid-column: ${col} / span 4;">${d.toLocaleDateString('en-US', { month: 'short' })}</div>`;
        currentMonth = d.getMonth();
      }
    }

    const tasks = state.dailyTasks[dateStr] || [];
    const count = tasks.length;
    const done = tasks.filter(t => t.done).length;

    let level = 'none';
    if (count > 0) {
      const pct = done / count;
      if (pct === 1) level = 4;
      else if (pct >= 0.67) level = 3;
      else if (pct >= 0.34) level = 2;
      else if (pct > 0) level = 1;
      else level = 0;
    }

    cellsHTML += `<div class="heatmap-cell level-${level}" style="grid-row: ${dayOfWeek + 2}; grid-column: ${col};" title="${d.toDateString()}: ${done}/${count} tasks completed"></div>`;
  }

  return `
    <div class="card" style="margin-top: 1.5rem;">
      <h3 class="card-title" style="margin-bottom: 1rem;">1-Year Consistency Tracker</h3>
      <div class="heatmap-container">
        <div class="heatmap">${cellsHTML}</div>
      </div>
      <div class="flex" style="justify-content: flex-end; align-items: center; gap: 0.5rem; font-size: 0.75rem; color: var(--text-muted); margin-top: 1rem;">
        <span>No Tasks</span>
        <div class="heatmap-cell level-none"></div>
        <div style="width: 10px;"></div>
        <span>0%</span>
        <div class="heatmap-cell level-0"></div>
        <div class="heatmap-cell level-1"></div>
        <div class="heatmap-cell level-2"></div>
        <div class="heatmap-cell level-3"></div>
        <div class="heatmap-cell level-4"></div>
        <span>100%</span>
      </div>
    </div>
  `;
}

function renderDashboard() {
  const today = new Date();
  const currentDayOfYear = getDayOfYear(today);
  const currentMonthStr = getYYYYMM(today);

  let dailyQuote = dailyQuotes.find(q => q.day === currentDayOfYear) ||
    dailyQuotes[(currentDayOfYear % dailyQuotes.length) || 0] ||
    { quote: "Set your goals high, and don't stop till you get there.", author: "Bo Jackson" };

  const mGoals = state.monthlyGoals[currentMonthStr] || [];
  const topGoal = mGoals.length > 0 ? mGoals[0] : null;

  const days = [];
  let totalTasks = 0;
  let totalDone = 0;

  for (let i = 6; i >= 0; i--) {
    const d = new Date(today);
    d.setDate(today.getDate() - i);
    const dateStr = getYYYYMMDD(d);
    const tasks = state.dailyTasks[dateStr] || [];
    const done = tasks.filter(t => t.done).length;
    const count = tasks.length;
    const percentage = count === 0 ? 0 : Math.round((done / count) * 100);

    totalTasks += count;
    totalDone += done;
    days.push({ label: d.toLocaleDateString('en-US', { weekday: 'short' }), percentage });
  }

  const avgCompletion = totalTasks === 0 ? 0 : Math.round((totalDone / totalTasks) * 100);

  setTimeout(() => {
    document.querySelectorAll('.bar').forEach(bar => {
      bar.style.height = bar.getAttribute('data-height');
    });
  }, 50);

  return `
    <div class="quote-card">
      <div class="quote-text">"${escapeHTML(dailyQuote.quote)}"</div>
      <div class="quote-author">&mdash; ${escapeHTML(dailyQuote.author)}</div>
    </div>

    <div class="card" style="border-left: 4px solid var(--warning); background: linear-gradient(to right, rgba(245, 158, 11, 0.05), var(--bg-surface));">
      <div class="flex" style="align-items: center; justify-content: space-between; margin-bottom: 0.5rem;">
        <h3 class="card-title" style="font-size: 1rem; color: var(--warning); display: flex; align-items: center; gap: 0.5rem;">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"></polygon></svg>
          Month's Primary Priority
        </h3>
        <span class="text-muted" style="font-size: 0.8rem; font-weight: 500;">${new Date().toLocaleDateString('en-US', { month: 'long', year: 'numeric' })}</span>
      </div>
      <p style="font-size: 1.125rem; font-weight: 600; color: var(--text-primary); margin-top: 0.5rem; ${topGoal && topGoal.done ? 'text-decoration: line-through; opacity: 0.6;' : ''}">
        ${topGoal ? escapeHTML(topGoal.text) : '<em>No primary goal set for this month. Set one in the Milestones tab.</em>'}
      </p>
    </div>

    <div class="grid grid-2">
      <div class="card" style="display: flex; flex-direction: column;">
        <h3 class="card-title" style="margin-bottom: 0.5rem;">7-Day Activity Stream</h3>
        <p class="text-muted">Completed <strong>${totalDone}</strong> out of <strong>${totalTasks}</strong> tasks.</p>
        <div class="chart-container">
          ${days.map(day => `
            <div class="bar-wrap" title="${day.percentage}%">
              <div class="bar" data-height="${day.percentage}%" style="height: 0%;"></div>
              <span class="bar-label">${day.label}</span>
            </div>
          `).join('')}
        </div>
      </div>
      
      <div class="flex" style="flex-direction: column; gap: 1.5rem;">
        <div class="card" style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 0;">
          <div>
            <h3 class="card-title" style="margin-bottom: 0.25rem;">Weekly Progress</h3>
            <p class="text-muted" style="font-size: 0.875rem;">Completion over the last 7 days</p>
          </div>
          <div class="progress-circle" style="--progress: ${avgCompletion}%">
            <span class="progress-value">${avgCompletion}%</span>
          </div>
        </div>

        <div class="card" style="margin-bottom: 0; flex: 1;">
          <h3 class="card-title" style="margin-bottom: 1rem;">Quick Shortcuts</h3>
          <div class="flex" style="flex-direction: column; gap: 0.75rem;">
            <button class="btn btn-primary" style="width: 100%;" onclick="window.location.hash='#/daily'">Log Daily Data</button>
            <button class="btn btn-secondary" style="width: 100%;" onclick="window.location.hash='#/weekly'">Set Milestones</button>
          </div>
        </div>
      </div>
    </div>
    
    ${renderHeatmap()}
  `;
}

// --- Views ---
function changeDate(offset) {
  selectedDate.setDate(selectedDate.getDate() + offset);
  renderView();
}

function setDateFromCard(dateString) {
  selectedDate = new Date(dateString + 'T00:00:00');
  renderView();
}

function renderDaily() {
  const startOfWeek = new Date(selectedDate);
  startOfWeek.setDate(selectedDate.getDate() - selectedDate.getDay());

  let stripHTML = '';
  for (let i = 0; i < 7; i++) {
    const d = new Date(startOfWeek);
    d.setDate(startOfWeek.getDate() + i);
    const dStr = getYYYYMMDD(d);
    const isSelected = dStr === getYYYYMMDD(selectedDate);
    stripHTML += `
      <div class="day-card ${isSelected ? 'active' : ''}" onclick="setDateFromCard('${dStr}')">
        <div class="day-name">${d.toLocaleDateString('en-US', { weekday: 'short' })}</div>
        <div class="day-date">${d.getDate()}</div>
      </div>
    `;
  }

  const dateStr = getYYYYMMDD(selectedDate);
  const tasks = state.dailyTasks[dateStr] || [];

  return `
    <div class="date-selector">
      <button class="btn btn-secondary" onclick="changeDate(-7)" title="Previous Week">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M15 18l-6-6 6-6"/></svg>
      </button>
      <div class="week-strip">${stripHTML}</div>
      <button class="btn btn-secondary" onclick="changeDate(7)" title="Next Week">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 18l6-6-6-6"/></svg>
      </button>
    </div>
    
    <div class="card">
      <h3 class="card-title" style="margin-bottom: 1.5rem;">Daily Execution: ${selectedDate.toLocaleDateString('en-US', { weekday: 'long', month: 'short', day: 'numeric' })}</h3>
      
      <form class="flex" style="margin-bottom: 2rem;" onsubmit="addDailyTask(event)">
        <input type="text" id="new-task-input" placeholder="What needs to be conquered today?" required autocomplete="off">
        <button type="submit" class="btn btn-primary" style="white-space: nowrap;">Add Task</button>
      </form>

      <div id="task-list">
        ${tasks.length === 0 ? '<div style="text-align: center; padding: 3rem 0; color: var(--text-muted); background: var(--bg-base); border-radius: 8px; border: 1px dashed var(--border-strong);">No tasks logged for this date. Start planning!</div>' : ''}
        ${tasks.map(t => `
          <div class="check-item ${t.done ? 'done' : ''}">
            <input type="checkbox" ${t.done ? 'checked' : ''} onchange="toggleDailyTask('${dateStr}', '${sanitizeId(t.id)}')">
            <div class="check-title">${escapeHTML(t.text)}</div>
            <button class="btn-delete" onclick="deleteDailyTask('${dateStr}', '${sanitizeId(t.id)}')" title="Delete Task">
               <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>
            </button>
          </div>
        `).join('')}
      </div>
    </div>
  `;
}

function renderWeekly() {
  const currentWeekStr = getWeekString(new Date());
  const currentMonthStr = getYYYYMM(new Date());

  const existingWeekInput = document.getElementById('week-selector');
  const activeWeekStr = existingWeekInput ? existingWeekInput.value : currentWeekStr;

  const existingMonthInput = document.getElementById('month-selector');
  const activeMonthStr = existingMonthInput ? existingMonthInput.value : currentMonthStr;

  const wGoals = state.weeklyGoals[activeWeekStr] || [];
  const mGoals = state.monthlyGoals[activeMonthStr] || [];

  const labels = ["1st Priority", "2nd Priority", "3rd Priority"];

  return `
    <!-- Monthly Goals Section -->
    <div class="card" style="border-top: 4px solid var(--warning);">
      <div class="flex" style="align-items: center; justify-content: space-between; margin-bottom: 1.5rem; flex-wrap: wrap;">
        <h3 class="card-title">Main Monthly Goals (Max 3)</h3>
        <input type="month" id="month-selector" value="${activeMonthStr}" onchange="renderView()" style="width: auto; cursor: pointer;">
      </div>
      
      ${mGoals.length < 3 ? `
      <form class="flex" style="margin-bottom: 2rem;" onsubmit="addMonthlyGoal(event)">
        <input type="text" id="new-monthly-input" placeholder="Define priority ${mGoals.length + 1} for this month..." required autocomplete="off">
        <button type="submit" class="btn btn-primary" style="white-space: nowrap;">Add Monthly</button>
      </form>` : '<div class="text-muted" style="margin-bottom: 2rem; font-size: 0.875rem;">You have defined your 3 main priorities for this month.</div>'}

      <div id="monthly-goal-list">
        ${mGoals.length === 0 ? '<div style="text-align: center; padding: 2rem 0; color: var(--text-muted); background: var(--bg-base); border-radius: 8px; border: 1px dashed var(--border-strong);">No monthly priorities set.</div>' : ''}
        ${mGoals.map((g, index) => `
          <div class="check-item ${g.done ? 'done' : ''}">
            <input type="checkbox" ${g.done ? 'checked' : ''} onchange="toggleMonthlyGoal('${activeMonthStr}', '${sanitizeId(g.id)}')">
            <div class="check-title flex" style="align-items: center; gap: 0.75rem;">
              <span class="priority-badge ${index === 0 ? 'priority-1' : ''}">${labels[index]}</span>${escapeHTML(g.text)}
            </div>
            <button class="btn-delete" onclick="deleteMonthlyGoal('${activeMonthStr}', '${sanitizeId(g.id)}')" title="Delete Goal">
               <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>
            </button>
          </div>
        `).join('')}
      </div>
    </div>

    <!-- Weekly Objectives Section -->
    <div class="card" style="border-top: 4px solid var(--accent);">
      <div class="flex" style="align-items: center; justify-content: space-between; margin-bottom: 1.5rem; flex-wrap: wrap;">
        <h3 class="card-title">Macro Weekly Objectives</h3>
        <input type="week" id="week-selector" value="${activeWeekStr}" onchange="renderView()" style="width: auto; cursor: pointer;">
      </div>
      
      <form class="flex" style="margin-bottom: 2rem;" onsubmit="addWeeklyGoal(event)">
        <input type="text" id="new-goal-input" placeholder="Define a major milestone for this week..." required autocomplete="off">
        <button type="submit" class="btn btn-primary" style="white-space: nowrap;">Add Weekly</button>
      </form>

      <div id="goal-list">
        ${wGoals.length === 0 ? '<div style="text-align: center; padding: 2rem 0; color: var(--text-muted); background: var(--bg-base); border-radius: 8px; border: 1px dashed var(--border-strong);">No weekly objectives set.</div>' : ''}
        ${wGoals.map(g => `
          <div class="check-item ${g.done ? 'done' : ''}">
            <input type="checkbox" ${g.done ? 'checked' : ''} onchange="toggleWeeklyGoal('${activeWeekStr}', '${sanitizeId(g.id)}')">
            <div class="check-title">${escapeHTML(g.text)}</div>
            <button class="btn-delete" onclick="deleteWeeklyGoal('${activeWeekStr}', '${sanitizeId(g.id)}')" title="Delete Goal">
               <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>
            </button>
          </div>
        `).join('')}
      </div>
    </div>
  `;
}

function renderSettings() {
  return `
    <div class="card">
      <h3 class="card-title" style="margin-bottom: 1rem;">System & Data Settings</h3>
      <p class="text-muted" style="margin-bottom: 2rem;">Everything is saved locally in your browser and updates automatically. Use these tools to secure your data.</p>
      
      <div class="grid grid-2">
        <div style="border: 1px solid var(--border-subtle); padding: 1.5rem; border-radius: 12px; background: var(--bg-elevated);">
          <h4 style="margin-bottom: 0.5rem; color: var(--text-primary);">Export Backup</h4>
          <p class="text-muted" style="font-size: 0.875rem; margin-bottom: 1.5rem;">Download a secure JSON copy of your complete timeline.</p>
          <button class="btn btn-primary" style="width: 100%;" onclick="exportData()">Download File</button>
        </div>
        
        <div style="border: 1px solid var(--border-subtle); padding: 1.5rem; border-radius: 12px; background: var(--bg-elevated);">
          <h4 style="margin-bottom: 0.5rem; color: var(--text-primary);">Restore Data</h4>
          <p class="text-muted" style="font-size: 0.875rem; margin-bottom: 1.5rem;">Upload a previous JSON backup to overwrite current state.</p>
          <label class="btn btn-secondary" style="width: 100%; display: flex; justify-content: center; cursor: pointer;">
            Select Backup File
            <input type="file" accept=".json" style="display: none;" onchange="importData(event)">
          </label>
        </div>
      </div>
      
      <div style="margin-top: 2rem; padding-top: 2rem; border-top: 1px solid var(--border-subtle);">
        <h4 style="margin-bottom: 0.5rem; color: var(--danger);">Danger Zone</h4>
        <p class="text-muted" style="font-size: 0.875rem; margin-bottom: 1rem;">Permanently delete all tasks, goals, and history.</p>
        <button class="btn btn-danger" onclick="resetData()">Factory Reset Data</button>
      </div>
    </div>
  `;
}

// --- Router Engine ---
function renderView() {
  const hash = window.location.hash || '#/dashboard';
  const route = hash.replace('#/', '');

  let readableTitle = route.charAt(0).toUpperCase() + route.slice(1);
  if (route === 'settings') readableTitle = 'Settings & Data';
  if (route === 'daily') readableTitle = 'Daily Execution';
  if (route === 'weekly') readableTitle = 'Monthly & Weekly Milestones';

  const titleEl = document.getElementById('page-title');
  if (titleEl) titleEl.textContent = readableTitle;

  document.querySelectorAll('.nav-link').forEach(link => {
    link.classList.toggle('active', link.getAttribute('data-route') === route);
  });

  const content = document.getElementById('content');
  if (content) {
    if (route === 'dashboard') content.innerHTML = renderDashboard();
    else if (route === 'daily') content.innerHTML = renderDaily();
    else if (route === 'weekly') content.innerHTML = renderWeekly();
    else if (route === 'settings') content.innerHTML = renderSettings();
    else content.innerHTML = `<div class="card"><p class="text-muted">404 - Module not found</p></div>`;
  }
}

// --- Expose functions to window for HTML event handlers ---
window.openMotivationModal = openMotivationModal;
window.closeMotivationModal = closeMotivationModal;
window.handleModalOverlayClick = handleModalOverlayClick;
window.addDailyTask = addDailyTask;
window.toggleDailyTask = toggleDailyTask;
window.deleteDailyTask = deleteDailyTask;
window.addMonthlyGoal = addMonthlyGoal;
window.toggleMonthlyGoal = toggleMonthlyGoal;
window.deleteMonthlyGoal = deleteMonthlyGoal;
window.addWeeklyGoal = addWeeklyGoal;
window.toggleWeeklyGoal = toggleWeeklyGoal;
window.deleteWeeklyGoal = deleteWeeklyGoal;
window.resetData = resetData;
window.exportData = exportData;
window.importData = importData;
window.changeDate = changeDate;
window.setDateFromCard = setDateFromCard;
window.renderView = renderView;

// --- Auth UI Listeners ---
document.getElementById('btn-login-email').addEventListener('click', async () => {
  const email = document.getElementById('auth-email').value;
  const password = document.getElementById('auth-password').value;
  const errDiv = document.getElementById('auth-error');
  if (!email || !password) { errDiv.textContent = 'Please enter email and password'; errDiv.style.display = 'block'; return; }
  try {
    errDiv.style.display = 'none';
    await signInWithEmailAndPassword(auth, email, password);
  } catch (err) {
    errDiv.textContent = err.message;
    errDiv.style.display = 'block';
  }
});

document.getElementById('btn-signup-email').addEventListener('click', async () => {
  const email = document.getElementById('auth-email').value;
  const password = document.getElementById('auth-password').value;
  const errDiv = document.getElementById('auth-error');
  if (!email || !password) { errDiv.textContent = 'Please enter email and password'; errDiv.style.display = 'block'; return; }
  try {
    errDiv.style.display = 'none';
    await createUserWithEmailAndPassword(auth, email, password);
  } catch (err) {
    errDiv.textContent = err.message;
    errDiv.style.display = 'block';
  }
});

document.getElementById('btn-login-google').addEventListener('click', async () => {
  const provider = new GoogleAuthProvider();
  try {
    await signInWithPopup(auth, provider);
  } catch (err) {
    document.getElementById('auth-error').textContent = err.message;
    document.getElementById('auth-error').style.display = 'block';
  }
});

const handleLogout = async () => {
  await signOut(auth);
};
document.getElementById('btn-logout-mobile').addEventListener('click', handleLogout);
document.getElementById('btn-logout-desktop').addEventListener('click', handleLogout);

// --- Lifecycle Event Listeners ---
window.addEventListener('hashchange', renderView);
window.addEventListener('load', () => {
  // Listen for auth state changes to show/hide app and load data
  onAuthStateChanged(auth, (user) => {
    const authView = document.getElementById('auth-view');
    const appView = document.getElementById('app');
    
    if (user) {
      currentUser = user;
      authView.style.display = 'none';
      appView.style.display = 'block';
      loadDataFromFirebase(user.uid);
    } else {
      currentUser = null;
      authView.style.display = 'flex';
      appView.style.display = 'none';
      state = { dailyTasks: {}, weeklyGoals: {}, monthlyGoals: {}, lastUpdate: null };
      initStateDefaults();
    }
  });
});
