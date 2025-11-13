<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>FinanceEase — Full CRUD (Subscriptions + Earnings + Undo)</title>
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <script src="https://cdn.tailwindcss.com"></script>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@100..900&display=swap');
    body { font-family: 'Inter', sans-serif; background-color: #f7f9fb; }
    .main-card { box-shadow: 0 10px 15px -3px rgba(0,0,0,0.1), 0 4px 6px -4px rgba(0,0,0,0.05); transition: transform 0.18s ease; }
    .main-card:hover { transform: translateY(-2px); }
    #sidebar { transition: width 0.3s ease, padding 0.3s ease; flex-shrink:0; height:100vh; position:sticky; top:0; overflow-x:hidden; }
    .sidebar-container.collapsed #sidebar { width:5rem; }
    .sidebar-container.collapsed .menu-item span, .sidebar-container.collapsed .sidebar-header, .sidebar-container.collapsed #user-display-id { display:none; opacity:0; transition:opacity 0.1s; }
    .sidebar-container.collapsed .menu-item { justify-content:center; }
    .sidebar-container.collapsed .menu-item svg { margin-right:0 !important; }
    .sidebar-container.collapsed #collapse-icon { transform: rotate(180deg); }
    .sidebar-container:not(.collapsed) #sidebar { width:16rem; }
    .sidebar-container:not(.collapsed) .menu-item span, .sidebar-container:not(.collapsed) .sidebar-header, .sidebar-container:not(.collapsed) #user-display-id { opacity:1; transition: opacity 0.3s 0.2s; }
    .loading-ring { border:4px solid rgba(255,255,255,0.3); border-top:4px solid #34d399; border-radius:50%; width:24px; height:24px; animation:spin 1s linear infinite; }
    @keyframes spin { 0%{transform:rotate(0deg);} 100%{transform:rotate(360deg);} }
    #toast-container { position: fixed; top: 1rem; right: 1rem; z-index: 60; display:flex; flex-direction:column; gap:0.5rem; align-items:flex-end; }
    .owner-photo { width:110px; height:110px; object-fit:cover; border-radius:9999px; }
    @media (max-width: 768px) {
      #sidebar { display: none; }
      .sidebar-container.collapsed #sidebar { display:block; }
    }
  </style>
</head>
<body class="min-h-screen flex flex-col">

  <!-- Toast container -->
  <div id="toast-container" aria-live="polite" aria-atomic="true"></div>

  <div id="main-content" class="w-full flex-1 flex">

    <!-- LOGIN VIEW -->
    <div id="login-view" class="w-full flex items-center justify-center p-6 min-h-screen bg-gray-100">
      <div class="main-card bg-white p-10 md:p-12 rounded-3xl w-full max-w-lg shadow-2xl">
        <div class="text-center mb-6">
          <h1 class="text-4xl font-extrabold text-gray-900">Finance<span class="text-emerald-500">Ease</span></h1>
          <p class="text-gray-500 mt-2">Sign in or create an account to persist your data</p>
        </div>

        <div id="auth-mode-switch" class="text-center mb-6">
          <button id="show-login-btn" class="px-4 py-2 bg-emerald-100 text-emerald-700 rounded-l-full border-r" onclick="showLoginForm()">Login</button>
          <button id="show-signup-btn" class="px-4 py-2 bg-transparent text-gray-600 rounded-r-full hover:bg-gray-50" onclick="showSignupForm()">Create account</button>
        </div>

        <form id="auth-form">
          <input type="hidden" id="auth-mode" value="login">
          <div class="mb-4">
            <label class="block text-sm font-medium text-gray-700 mb-2">Email</label>
            <input id="auth-email" type="email" required class="w-full p-3 border border-gray-300 rounded-xl bg-gray-50" placeholder="you@example.com" />
          </div>
          <div class="mb-6">
            <label class="block text-sm font-medium text-gray-700 mb-2">Password</label>
            <input id="auth-password" type="password" required class="w-full p-3 border border-gray-300 rounded-xl bg-gray-50" placeholder="Choose a password" />
          </div>

          <div class="flex justify-between items-center">
            <button id="auth-submit-btn" type="submit" class="px-6 py-3 bg-emerald-500 text-white rounded-xl font-semibold">Sign in</button>
            <div class="text-sm text-gray-500 flex gap-3 items-center">
              <a href="#" class="guest-link text-blue-500 hover:underline">Continue as guest</a>
              <button id="use-mock-btn" type="button" class="px-3 py-1 bg-gray-100 rounded-md text-sm hover:bg-gray-200">Use Mock Account</button>
            </div>
          </div>
        </form>

        <p class="text-xs text-gray-400 mt-4">Note: This prototype is local-only. Firestore persistence can be added later.</p>
      </div>
    </div>

    <!-- COVER VIEW -->
    <div id="cover-view" class="hidden w-full flex items-center justify-center p-6 min-h-screen bg-gradient-to-br from-white to-gray-50">
      <div class="main-card bg-white p-8 md:p-12 rounded-3xl w-full max-w-4xl shadow-2xl">
        <div class="text-center mb-6">
          <h2 class="text-4xl font-bold text-gray-800">Welcome to FinanceEase</h2>
          <p class="text-gray-500 mt-2">Small, smart finance for students — built with ❤️ by the owners below.</p>
        </div>

        <div id="owners" class="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6"></div>

        <div class="text-center mt-6">
          <button onclick="continueToApp()" class="px-8 py-3 bg-emerald-500 text-white rounded-xl font-semibold hover:bg-emerald-600">Continue to Dashboard</button>
        </div>
      </div>
    </div>

    <!-- APP VIEW -->
    <div id="app-view" class="hidden w-full flex-1 flex sidebar-container">
      <!-- Sidebar -->
      <div id="sidebar" class="bg-gray-800 text-white p-5 space-y-4 shadow-xl flex flex-col">
        <div class="sidebar-header text-2xl font-extrabold text-emerald-400 mb-6 border-b border-gray-700 pb-3 h-10 overflow-hidden">FinanceEase</div>

        <a id="dashboard-menu" href="#" class="menu-item p-3 rounded-xl flex items-center space-x-3 hover:bg-gray-700" onclick="showDashboard()">
          <svg class="w-6 h-6 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6"></path></svg>
          <span class="font-medium">Dashboard</span>
        </a>

        <a id="budget-menu" href="#" class="menu-item p-3 rounded-xl flex items-center space-x-3 hover:bg-gray-700" onclick="showBudget()">
          <svg class="w-6 h-6 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8c-1.657 0-3 .895-3 2s1.343 2 3 2 3 .895 3 2-1.343 2-3 2m0-8c1.11 0 2.08.402 2.599 1M12 8H7a2 2 0 00-2 2v4a2 2 0 002 2h5m-2-4h4m1 4h-2.583m-1.25-8l-1.5 5.5"></path></svg>
          <span class="font-medium">Budget & Goals</span>
        </a>

        <a id="recurring-menu" href="#" class="menu-item p-3 rounded-xl flex items-center space-x-3 hover:bg-gray-700" onclick="showRecurring()">
          <svg class="w-6 h-6 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path></svg>
          <span class="font-medium">Recurring Expenses</span>
        </a>

        <a id="money-menu" href="#" class="menu-item p-3 rounded-xl flex items-center space-x-3 hover:bg-gray-700" onclick="showMoney()">
          <svg class="w-6 h-6 flex-shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8c-1.657 0-3 .895-3 2s1.343 2 3 2 3 .895 3 2-1.343 2-3 2"></path></svg>
          <span class="font-medium">Money Earned</span>
        </a>

        <a id="ai-insight-menu" href="#" class="menu-item p-3 rounded-xl flex items-center space-x-3 hover:bg-gray-700" onclick="showAIInsight()">
          <svg class="w-6 h-6 flex-shrink-0 text-yellow-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.663 17h4.673M12 17v2m-8 3h16a1 1 0 001-1V5a1 1 0 00-1-1H3a1 1 0 00-1 1v12a1 1 0 001 1zm-1-8h20"></path></svg>
          <span class="font-semibold text-yellow-300">AI Insights</span>
        </a>

        <div class="mt-auto pt-6 border-t border-gray-700">
          <p id="user-display-id" class="text-xs text-gray-500 truncate overflow-hidden">User ID: Loading...</p>
        </div>
      </div>

      <!-- Main Content Area -->
      <div id="main-content-area" class="flex-1 overflow-y-auto bg-gray-50">
        <header class="flex items-center justify-between p-4 md:p-6 bg-white border-b sticky top-0 z-10 shadow-sm">
          <div class="flex items-center space-x-4">
            <button id="toggle-sidebar-btn" class="p-2 rounded-full text-gray-500 hover:bg-gray-100" onclick="toggleSidebar()">
              <svg id="collapse-icon" class="w-6 h-6 transition-transform duration-300" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 5l7 7-7 7M5 5l7 7-7 7"></path></svg>
            </button>
            <h1 id="view-title" class="text-2xl font-bold text-gray-800">Dashboard Overview</h1>
          </div>

          <div class="flex items-center gap-3">
            <button id="open-add-expense" class="bg-emerald-500 hover:bg-emerald-600 text-white font-semibold py-2 px-4 rounded-xl flex items-center" onclick="openAddExpenseModal()">
              <svg class="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6v6m0 0v6m0-6h6m-6 0H6"></path></svg>
              Add New Expense
            </button>
            <button id="open-ai-btn" class="bg-yellow-400 hover:bg-yellow-500 text-white font-semibold py-2 px-3 rounded-xl" onclick="showAIInsight()">AI</button>
            <button id="signout-btn" class="bg-gray-100 hover:bg-gray-200 text-gray-700 py-2 px-3 rounded-xl hidden" onclick="handleSignOut()">Sign out</button>
          </div>
        </header>

        <div class="p-4 md:p-6">
          <!-- Dashboard -->
          <div id="dashboard-view">
            <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
              <div class="main-card bg-white p-6 rounded-2xl border-b-4 border-emerald-500">
                <h2 class="text-md font-medium text-gray-500">Money Spent</h2>
                <p id="money-spent-amount" class="text-4xl font-extrabold text-emerald-600 mt-2">₹0.00</p>
                <p id="money-spent-sub" class="text-sm mt-3 text-gray-400">Total expenses recorded</p>
              </div>
              <div class="main-card bg-white p-6 rounded-2xl border-b-4 border-yellow-500">
                <h2 class="text-md font-medium text-gray-500">Daily Burn Rate</h2>
                <p id="daily-burn" class="text-4xl font-extrabold text-gray-800 mt-2">₹450.00</p>
                <p class="text-sm mt-3 text-gray-400">vs. ₹500.00 average target</p>
              </div>
              <div class="main-card bg-white p-6 rounded-2xl border-b-4 border-blue-500">
                <h2 class="text-md font-medium text-gray-500">Savings Goal Progress</h2>
                <p id="savings-goal-progress" class="text-4xl font-extrabold text-blue-600 mt-2">60%</p>
                <p id="savings-goal-sub" class="text-sm mt-3 text-gray-400">Laptop Fund (₹52,000 / ₹70,000)</p>
              </div>
              <div class="main-card bg-white p-6 rounded-2xl border-b-4 border-purple-500">
                <h2 class="text-md font-medium text-gray-500">Upcoming Bills</h2>
                <p id="upcoming-bills-count" class="text-4xl font-extrabold text-purple-600 mt-2">0</p>
                <p id="upcoming-bills-sub" class="text-sm mt-3 text-gray-400">Totaling ₹0.00 in 30 days</p>
              </div>
            </div>

            <div class="main-card bg-white p-6 rounded-2xl mb-6">
              <h2 class="text-xl font-semibold text-gray-700 mb-4">Recent Transactions</h2>
              <div class="overflow-x-auto">
                <table class="min-w-full divide-y divide-gray-200">
                  <thead>
                    <tr class="bg-gray-50">
                      <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase rounded-tl-lg">Date</th>
                      <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Description</th>
                      <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Category</th>
                      <th class="px-4 py-3 text-right text-xs font-medium text-gray-500 uppercase">Amount</th>
                      <th class="px-4 py-3 text-center text-xs font-medium text-gray-500 uppercase rounded-tr-lg">Actions</th>
                    </tr>
                  </thead>
                  <tbody id="transactions-list" class="bg-white divide-y divide-gray-200"></tbody>
                </table>
              </div>
            </div>

            <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
              <div class="main-card bg-white p-6 rounded-2xl">
                <h3 class="text-lg font-semibold text-gray-700 mb-2">Monthly Budgets Snapshot</h3>
                <div id="budgets-brief" class="text-sm text-gray-500"></div>
              </div>

              <div class="main-card bg-white p-6 rounded-2xl">
                <h3 class="text-lg font-semibold text-gray-700 mb-2">Total Income</h3>
                <p id="total-income" class="text-2xl font-bold text-emerald-600">₹0.00</p>
                <p class="text-sm text-gray-500">Sum of recorded money earned</p>
              </div>

              <div class="main-card bg-white p-6 rounded-2xl">
                <h3 class="text-lg font-semibold text-gray-700 mb-2">Total Expenses</h3>
                <p id="total-expenses" class="text-2xl font-bold text-red-600">₹0.00</p>
                <p class="text-sm text-gray-500">Sum of recorded transactions</p>
              </div>
            </div>

          </div>

          <!-- Budget & Goals -->
          <div id="budget-view" class="hidden">
            <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <div class="main-card bg-white p-6 rounded-2xl">
                <h3 class="text-2xl font-bold text-gray-800 mb-6 border-b pb-2 flex justify-between items-center">
                  Monthly Budgets
                  <button class="text-sm bg-blue-100 text-blue-700 px-3 py-1 rounded-full hover:bg-blue-200" onclick="openAddBudgetModal()">Set New</button>
                </h3>
                <div class="overflow-x-auto">
                  <table class="min-w-full divide-y divide-gray-200">
                    <thead>
                      <tr class="bg-gray-50">
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Category</th>
                        <th class="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase">Limit</th>
                        <th class="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase">Spent</th>
                        <th class="px-6 py-3 text-center text-xs font-medium text-gray-500 uppercase">Status</th>
                      </tr>
                    </thead>
                    <tbody id="budgets-list" class="bg-white divide-y divide-gray-200"></tbody>
                  </table>
                </div>
              </div>

              <div class="main-card bg-white p-6 rounded-2xl">
                <h3 class="text-2xl font-bold text-gray-800 mb-6 border-b pb-2 flex justify-between items-center">
                  Financial Goals
                  <button class="text-sm bg-emerald-100 text-emerald-700 px-3 py-1 rounded-full hover:bg-emerald-200" onclick="openAddGoalModal()">Add Goal</button>
                </h3>
                <div id="goals-list" class="space-y-4"></div>
              </div>
            </div>
          </div>

          <!-- Recurring -->
          <div id="recurring-view" class="hidden">
            <div class="main-card bg-white p-6 rounded-2xl">
              <h3 class="text-2xl font-bold text-gray-800 mb-6 border-b pb-2 flex justify-between items-center">
                Subscriptions & Recurring Bills
                <button class="text-sm bg-purple-100 text-purple-700 px-3 py-1 rounded-full hover:bg-purple-200" onclick="openSubscriptionModal()">Add Subscription</button>
              </h3>
              <div class="overflow-x-auto">
                <table class="min-w-full divide-y divide-gray-200">
                  <thead>
                    <tr class="bg-gray-50">
                      <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Expense Name</th>
                      <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Category</th>
                      <th class="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase">Amount</th>
                      <th class="px-6 py-3 text-center text-xs font-medium text-gray-500 uppercase">Frequency</th>
                      <th class="px-6 py-3 text-center text-xs font-medium text-gray-500 uppercase">Next Due</th>
                      <th class="px-6 py-3 text-center text-xs font-medium text-gray-500 uppercase">Actions</th>
                    </tr>
                  </thead>
                  <tbody id="recurring-list" class="bg-white divide-y divide-gray-200"></tbody>
                </table>
              </div>
            </div>
          </div>

          <!-- Money Earned -->
          <div id="money-view" class="hidden">
            <div class="main-card bg-white p-6 rounded-2xl">
              <h3 class="text-2xl font-bold text-gray-800 mb-6 border-b pb-2 flex justify-between items-center">
                Money Earned
                <button class="text-sm bg-emerald-100 text-emerald-700 px-3 py-1 rounded-full hover:bg-emerald-200" onclick="openAddEarningModal()">Add Earning</button>
              </h3>
              <div class="overflow-x-auto">
                <table class="min-w-full divide-y divide-gray-200">
                  <thead>
                    <tr class="bg-gray-50">
                      <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Source</th>
                      <th class="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase">Amount (₹)</th>
                      <th class="px-6 py-3 text-center text-xs font-medium text-gray-500 uppercase">Actions</th>
                    </tr>
                  </thead>
                  <tbody id="earnings-list" class="bg-white divide-y divide-gray-200"></tbody>
                </table>
              </div>
            </div>
          </div>

          <!-- AI -->
          <div id="ai-insight-view" class="hidden">
            <div class="max-w-3xl main-card bg-white p-8 rounded-2xl mx-auto">
              <p class="text-lg text-gray-600 mb-6">Ask for a personalized tip, a spending summary, or a forecast based on your current data.</p>
              <textarea id="user-prompt" class="w-full p-3 border border-gray-300 rounded-lg mb-4 resize-none" rows="3" placeholder="Example: Give me one actionable tip to save money this week."></textarea>
              <button id="generate-insight-btn" class="w-full bg-emerald-500 hover:bg-emerald-600 text-white font-semibold py-3 rounded-xl" onclick="fetchAiInsight()">
                <span id="btn-text">Generate Insight</span>
                <div id="btn-spinner" class="loading-ring hidden ml-3" style="display:inline-block"></div>
              </button>

              <div id="insight-result-box" class="mt-8 p-6 bg-gray-50 rounded-xl border-l-4 border-emerald-500 hidden">
                <h3 class="text-xl font-bold text-gray-700 mb-2">FinanceEase AI Report</h3>
                <p id="insight-text" class="text-gray-700 leading-relaxed"></p>
              </div>
            </div>
          </div>

        </div>
      </div>
    </div>

  </div>

  <!-- Add / Edit Expense Modal -->
  <div id="add-expense-modal" class="fixed inset-0 bg-gray-900 bg-opacity-75 flex items-center justify-center z-50 hidden p-4" onclick="closeAddExpenseModal(event)">
    <div class="bg-white rounded-3xl p-8 w-full max-w-lg main-card" onclick="event.stopPropagation()">
      <h2 id="expense-modal-title" class="text-3xl font-bold text-gray-800 mb-4 border-b pb-3">Record New Transaction</h2>
      <form id="expense-form" onsubmit="addOrEditExpense(event)">
        <input type="hidden" id="expense-edit-id" value="">
        <div class="grid grid-cols-1 sm:grid-cols-2 gap-6 mb-6">
          <div>
            <label class="block text-sm font-medium text-gray-700 mb-2">Amount (₹)</label>
            <input id="expense-amount" type="number" step="0.01" required class="w-full p-3 border border-gray-300 rounded-xl bg-gray-50" placeholder="e.g., 450.20">
          </div>
          <div>
            <label class="block text-sm font-medium text-gray-700 mb-2">Date</label>
            <input id="expense-date" type="date" required class="w-full p-3 border border-gray-300 rounded-xl bg-gray-50">
          </div>
        </div>

        <div class="mb-6">
          <label class="block text-sm font-medium text-gray-700 mb-2">Description</label>
          <input id="expense-description" type="text" required class="w-full p-3 border border-gray-300 rounded-xl bg-gray-50" placeholder="What did you buy?">
        </div>

        <div class="mb-8">
          <label class="block text-sm font-medium text-gray-700 mb-2">Category</label>
          <select id="expense-category" required class="w-full p-3 border border-gray-300 rounded-xl bg-gray-50">
            <option value="" disabled>Select a category</option>
            <option value="Groceries">Groceries</option>
            <option value="Rent/Utilities">Rent/Utilities</option>
            <option value="Textbooks/Supplies">Textbooks/Supplies</option>
            <option value="Transport">Transport</option>
            <option value="Social/Fun">Social/Fun</option>
            <option value="Recurring">Recurring</option>
            <option value="Other">Other</option>
          </select>
        </div>

        <div class="flex justify-end space-x-4">
          <button type="button" onclick="closeAddExpenseModal()" class="px-6 py-3 border border-gray-300 text-gray-700 rounded-xl">Cancel</button>
          <button id="expense-save-btn" type="submit" class="px-6 py-3 bg-emerald-500 text-white rounded-xl font-bold">Save Expense</button>
        </div>
      </form>
    </div>
  </div>

  <!-- Subscription Modal -->
  <div id="subscription-modal" class="fixed inset-0 bg-gray-900 bg-opacity-75 flex items-center justify-center z-50 hidden p-4" onclick="closeSubscriptionModal(event)">
    <div class="bg-white rounded-3xl p-6 w-full max-w-lg main-card" onclick="event.stopPropagation()">
      <h3 id="subscription-modal-title" class="text-xl font-bold mb-4">Add Subscription</h3>
      <form id="subscription-form" onsubmit="addOrEditSubscription(event)">
        <input type="hidden" id="subscription-edit-id">
        <div class="grid grid-cols-1 gap-4">
          <div>
            <label class="block text-sm text-gray-600 mb-1">Name</label>
            <input id="subscription-name" class="w-full p-3 border rounded-xl" required />
          </div>
          <div class="grid grid-cols-2 gap-4">
            <div>
              <label class="block text-sm text-gray-600 mb-1">Amount (₹)</label>
              <input id="subscription-amount" type="number" step="0.01" class="w-full p-3 border rounded-xl" required />
            </div>
            <div>
              <label class="block text-sm text-gray-600 mb-1">Frequency</label>
              <select id="subscription-frequency" class="w-full p-3 border rounded-xl" required>
                <option value="Monthly">Monthly</option>
                <option value="Weekly">Weekly</option>
                <option value="Yearly">Yearly</option>
              </select>
            </div>
          </div>
          <div>
            <label class="block text-sm text-gray-600 mb-1">Category</label>
            <input id="subscription-category" class="w-full p-3 border rounded-xl" placeholder="e.g., Entertainment" required />
          </div>
          <div>
            <label class="block text-sm text-gray-600 mb-1">Next Due (YYYY-MM-DD)</label>
            <input id="subscription-nextdue" type="date" class="w-full p-3 border rounded-xl" required />
          </div>
        </div>

        <div class="flex justify-end gap-3 mt-4">
          <button type="button" onclick="closeSubscriptionModal()" class="px-4 py-2 border rounded-lg">Cancel</button>
          <button type="submit" class="px-4 py-2 bg-purple-500 text-white rounded-lg">Save</button>
        </div>
      </form>
    </div>
  </div>

  <!-- Earning Modal -->
  <div id="earning-modal" class="fixed inset-0 bg-gray-900 bg-opacity-75 flex items-center justify-center z-50 hidden p-4" onclick="closeEarningModal(event)">
    <div class="bg-white rounded-3xl p-6 w-full max-w-md main-card" onclick="event.stopPropagation()">
      <h3 id="earning-modal-title" class="text-xl font-bold mb-4">Add Earning</h3>
      <form id="earning-form" onsubmit="addOrEditEarning(event)">
        <input type="hidden" id="earning-edit-id">
        <div class="grid grid-cols-1 gap-4">
          <div>
            <label class="block text-sm text-gray-600 mb-1">Source</label>
            <input id="earning-source" class="w-full p-3 border rounded-xl" required />
          </div>
          <div>
            <label class="block text-sm text-gray-600 mb-1">Amount (₹)</label>
            <input id="earning-amount" type="number" step="0.01" class="w-full p-3 border rounded-xl" required />
          </div>
        </div>

        <div class="flex justify-end gap-3 mt-4">
          <button type="button" onclick="closeEarningModal()" class="px-4 py-2 border rounded-lg">Cancel</button>
          <button type="submit" class="px-4 py-2 bg-emerald-500 text-white rounded-lg">Save</button>
        </div>
      </form>
    </div>
  </div>

  <!-- Budget Modal -->
<div id="budget-modal" class="fixed inset-0 bg-gray-900 bg-opacity-75 flex items-center justify-center z-50 hidden p-4" onclick="closeBudgetModal(event)">
  <div class="bg-white rounded-3xl p-6 w-full max-w-lg main-card" onclick="event.stopPropagation()">
    <h3 id="budget-modal-title" class="text-xl font-bold mb-4">Set New Budget</h3>
    <form id="budget-form" onsubmit="addOrEditBudget(event)">
      <input type="hidden" id="budget-edit-index" value="">
      <div class="grid grid-cols-1 gap-4">
        <div>
          <label class="block text-sm text-gray-600 mb-1">Category</label>
          <input id="budget-category" class="w-full p-3 border rounded-xl" placeholder="e.g., Groceries" required />
        </div>
        <div class="grid grid-cols-2 gap-4">
          <div>
            <label class="block text-sm text-gray-600 mb-1">Limit (₹)</label>
            <input id="budget-limit" type="number" step="0.01" class="w-full p-3 border rounded-xl" required />
          </div>
          <div>
            <label class="block text-sm text-gray-600 mb-1">Currently Spent (₹)</label>
            <input id="budget-spent" type="number" step="0.01" class="w-full p-3 border rounded-xl" value="0" />
          </div>
        </div>
      </div>

      <div class="flex justify-end gap-3 mt-4">
        <button type="button" onclick="closeBudgetModal()" class="px-4 py-2 border rounded-lg">Cancel</button>
        <button type="submit" class="px-4 py-2 bg-blue-600 text-white rounded-lg">Save Budget</button>
      </div>
    </form>
  </div>
</div>

<!-- Goal Modal -->
<div id="goal-modal" class="fixed inset-0 bg-gray-900 bg-opacity-75 flex items-center justify-center z-50 hidden p-4" onclick="closeGoalModal(event)">
  <div class="bg-white rounded-3xl p-6 w-full max-w-md main-card" onclick="event.stopPropagation()">
    <h3 id="goal-modal-title" class="text-xl font-bold mb-4">Add Goal</h3>
    <form id="goal-form" onsubmit="addOrEditGoal(event)">
      <input type="hidden" id="goal-edit-index" value="">
      <div class="grid grid-cols-1 gap-4">
        <div>
          <label class="block text-sm text-gray-600 mb-1">Goal Name</label>
          <input id="goal-name" class="w-full p-3 border rounded-xl" placeholder="e.g., Laptop Fund" required />
        </div>
        <div class="grid grid-cols-2 gap-4">
          <div>
            <label class="block text-sm text-gray-600 mb-1">Target (₹)</label>
            <input id="goal-target" type="number" step="0.01" class="w-full p-3 border rounded-xl" required />
          </div>
          <div>
            <label class="block text-sm text-gray-600 mb-1">Saved (₹)</label>
            <input id="goal-saved" type="number" step="0.01" class="w-full p-3 border rounded-xl" value="0" />
          </div>
        </div>
        <div>
          <label class="block text-sm text-gray-600 mb-1">Target Date</label>
          <input id="goal-date" type="date" class="w-full p-3 border rounded-xl" required />
        </div>
      </div>

      <div class="flex justify-end gap-3 mt-4">
        <button type="button" onclick="closeGoalModal()" class="px-4 py-2 border rounded-lg">Cancel</button>
        <button type="submit" class="px-4 py-2 bg-emerald-600 text-white rounded-lg">Save Goal</button>
      </div>
    </form>
  </div>
</div>


<script>
/* ----------------- App State ----------------- */
let MOCK_TRANSACTIONS = [
  { id: 1, date: "2025-11-08", description: "Monthly Rent/PG Fee", category: "Rent/Utilities", amount: 10000.00 },
  { id: 2, date: "2025-11-09", description: "Chai and Snacks", category: "Social/Fun", amount: 150.00 },
  { id: 3, date: "2025-11-09", description: "Textbook Purchase", category: "Textbooks/Supplies", amount: 500.00 },
  { id: 4, date: "2025-11-10", description: "Weekly Groceries", category: "Groceries", amount: 500.00 },
  { id: 5, date: "2025-11-10", description: "Netflix Subscription", category: "Recurring", amount: 199.00 },
  { id: 6, date: "2025-11-10", description: "Metro Card Recharge", category: "Transport", amount: 500.00 },
];

let MOCK_BUDGETS = [
  { category: "Groceries", limit: 3000, spent: 500, status: "Good" },
  { category: "Social/Fun", limit: 2000, spent: 150, status: "Good" },
  { category: "Transport", limit: 2000, spent: 500, status: "Good" },
];

let MOCK_GOALS = [
  { name: "Laptop Fund", target: 70000, saved: 52000, date: "2026-03-01" },
  { name: "Vacation Trip", target: 20000, saved: 5000, date: "2026-07-01" },
];

let MOCK_RECURRING_EXPENSES = [
  { id: 1, name: "Netflix Premium", category: "Entertainment", amount: 199.00, frequency: "Monthly", nextDue: "2025-11-25" },
  { id: 2, name: "Gym Membership", category: "Health", amount: 1000.00, frequency: "Monthly", nextDue: "2025-12-01" },
  { id: 3, name: "Internet Bill", category: "Rent/Utilities", amount: 499.00, frequency: "Monthly", nextDue: "2025-11-28" },
];

let MOCK_EARNINGS = [
  { id: 1, source: "mumma", amount: 2000.00 },
  { id: 2, source: "papa", amount: 1500.00 },
  { id: 3, source: "riyansh", amount: 3000.00 },
];

const OWNERS = [
  { name: "Aditi Rana", desc: "Student • 2nd Year • B.Tech (IT)", quote: "Smart finance isn’t about making cuts — it’s about making choices." },
  { name: "Bhoomika Garg", desc: "Student • 2nd Year • B.Tech (IT)", quote: "Innovation grows when patience and curiosity work together." }
];

/* For undo support */
let lastDeleted = null; // { type: 'transaction'|'subscription'|'earning', item: {...}, index: number }

/* ----------------- Toast w/ Undo support ----------------- */
function showToast(message, type='success', duration=4000, undoCallback=null) {
  const container = document.getElementById('toast-container');
  if (!container) return;
  const id = 'toast-' + Date.now();
  const bg = type === 'error' ? 'bg-red-500' : 'bg-emerald-500';
  const undoHtml = undoCallback ? `<button id="${id}-undo" class="ml-3 underline font-semibold">Undo</button>` : '';
  const html = `<div id="${id}" class="text-white ${bg} px-4 py-3 rounded-lg shadow-lg max-w-sm flex items-center justify-between gap-3">
    <div class="flex-1">${message}</div>
    <div>${undoHtml}</div>
  </div>`;
  container.insertAdjacentHTML('beforeend', html);
  const el = document.getElementById(id);

  if (undoCallback) {
    document.getElementById(id + '-undo').addEventListener('click', () => {
      undoCallback();
      if (el) el.remove();
    });
  }

  setTimeout(() => {
    if (!el) return;
    el.style.transition = 'opacity 300ms, transform 300ms';
    el.style.opacity = '0';
    el.style.transform = 'translateX(12px)';
    setTimeout(() => el.remove(), 350);
  }, duration);
}

/* ----------------- Utilities ----------------- */
function toggleSidebar() {
  const appView = document.getElementById('app-view');
  appView.classList.toggle('collapsed');
}

/* ----------------- View switching ----------------- */
function switchView(viewId, menuId, title) {
  const views = ['dashboard-view','budget-view','recurring-view','money-view','ai-insight-view'];
  views.forEach(v => document.getElementById(v).classList.add('hidden'));
  document.getElementById(viewId).classList.remove('hidden');
  document.getElementById('view-title').textContent = title || 'FinanceEase';
  document.querySelectorAll('.menu-item').forEach(m => m.classList.remove('bg-gray-700'));
  if (menuId) document.getElementById(menuId).classList.add('bg-gray-700');
}
function showDashboard(){ switchView('dashboard-view','dashboard-menu','Dashboard Overview'); }
function showBudget(){ loadBudgetGoals(); switchView('budget-view','budget-menu','Budgeting & Goals'); }
function showRecurring(){ loadRecurringExpenses(); switchView('recurring-view','recurring-menu','Recurring Expenses'); }
function showMoney(){ loadEarningsList(); switchView('money-view','money-menu','Money Earned'); }
function showAIInsight(){ switchView('ai-insight-view','ai-insight-menu','AI Insight Generator'); }

/* ----------------- Auth / Cover ----------------- */
function showLoginForm() {
  document.getElementById('login-view').classList.remove('hidden');
  document.getElementById('cover-view').classList.add('hidden');
  document.getElementById('app-view').classList.add('hidden');
  document.getElementById('auth-mode').value = 'login';
  document.getElementById('auth-submit-btn').textContent = 'Sign in';
}
function showSignupForm(){
  document.getElementById('auth-mode').value = 'signup';
  document.getElementById('auth-submit-btn').textContent = 'Create account';
}
function mockSignInDirect(email){
  const uid = 'mock-' + btoa(email).slice(0,12);
  document.getElementById('user-display-id').textContent = `User ID: ${uid} (mock)`;
  showToast(`Signed in (mock) as ${email}`, 'success');
  showCoverView();
}
function useGuestMode(){
  document.getElementById('user-display-id').textContent = 'Guest (local)';
  showToast('Guest mode active — not persisted.', 'success');
  showAppView();
}
function showCoverView(){
  const ownersEl = document.getElementById('owners');
  ownersEl.innerHTML = '';
  OWNERS.forEach(o => {
    const div = document.createElement('div');
    div.className = 'p-6 rounded-xl border bg-gray-50 text-center';
    div.innerHTML = `<h4 class="text-lg font-semibold text-gray-800">${o.name}</h4><p class="text-sm text-gray-500 mt-2">${o.desc}</p><blockquote class="text-sm text-gray-600 italic mt-3">"${o.quote}"</blockquote>`;
    ownersEl.appendChild(div);
  });
  document.getElementById('login-view').classList.add('hidden');
  document.getElementById('cover-view').classList.remove('hidden');
  document.getElementById('app-view').classList.add('hidden');
}
function continueToApp(){ document.getElementById('cover-view').classList.add('hidden'); showAppView(); }
function showAppView(){ document.getElementById('login-view').classList.add('hidden'); document.getElementById('cover-view').classList.add('hidden'); document.getElementById('app-view').classList.remove('hidden'); document.getElementById('signout-btn').classList.remove('hidden'); updateDashboardMetrics(); showDashboard(); }
function handleSignOut(){ document.getElementById('user-display-id').textContent='User ID: Loading...'; document.getElementById('signout-btn').classList.add('hidden'); showLoginForm(); showToast('Signed out.'); }

/* ----------------- Transactions CRUD (unchanged) ----------------- */
function openAddExpenseModal(){
  document.getElementById('expense-modal-title').textContent = 'Record New Transaction';
  document.getElementById('expense-save-btn').textContent = 'Save Expense';
  document.getElementById('expense-edit-id').value = '';
  document.getElementById('expense-form').reset();
  document.getElementById('add-expense-modal').classList.remove('hidden');
  document.getElementById('expense-date').valueAsDate = new Date();
}
function closeAddExpenseModal(event){
  if (!event || event.target === document.getElementById('add-expense-modal') || event.target.tagName === 'BUTTON') {
    document.getElementById('add-expense-modal').classList.add('hidden');
    document.getElementById('expense-form').reset();
    document.getElementById('expense-edit-id').value = '';
  }
}
function addOrEditExpense(e){
  e.preventDefault();
  const id = document.getElementById('expense-edit-id').value;
  const amount = parseFloat(document.getElementById('expense-amount').value);
  const date = document.getElementById('expense-date').value;
  const description = document.getElementById('expense-description').value.trim();
  const category = document.getElementById('expense-category').value;
  if (!amount || !date || !description || !category) { showToast('Please fill all fields','error'); return; }
  if (id) {
    const idx = MOCK_TRANSACTIONS.findIndex(t => String(t.id) === String(id));
    if (idx !== -1) {
      MOCK_TRANSACTIONS[idx] = {...MOCK_TRANSACTIONS[idx], amount, date, description, category};
      showToast('Transaction updated.');
    } else showToast('Not found','error');
  } else {
    const newId = (MOCK_TRANSACTIONS.length ? Math.max(...MOCK_TRANSACTIONS.map(t=>t.id)) : 0) + 1;
    MOCK_TRANSACTIONS.push({ id: newId, amount, date, description, category });
    showToast('Transaction added.');
  }
  MOCK_TRANSACTIONS.sort((a,b) => new Date(b.date) - new Date(a.date));
  closeAddExpenseModal();
  updateDashboardMetrics();
  loadDashboardData();
}
function editExpense(id){
  const item = MOCK_TRANSACTIONS.find(t=>String(t.id)===String(id));
  if(!item){ showToast('Transaction not found','error'); return; }
  document.getElementById('expense-edit-id').value = item.id;
  document.getElementById('expense-amount').value = item.amount;
  document.getElementById('expense-date').value = item.date;
  document.getElementById('expense-description').value = item.description;
  document.getElementById('expense-category').value = item.category;
  document.getElementById('expense-modal-title').textContent = 'Edit Transaction';
  document.getElementById('expense-save-btn').textContent = 'Save Changes';
  document.getElementById('add-expense-modal').classList.remove('hidden');
}
function deleteExpense(id){
  const item = MOCK_TRANSACTIONS.find(t=>String(t.id)===String(id));
  if(!item){ showToast('Transaction not found','error'); return; }
  // remove, but enable undo via toast
  const index = MOCK_TRANSACTIONS.findIndex(t=>String(t.id)===String(id));
  lastDeleted = { type:'transaction', item: {...item}, index };
  MOCK_TRANSACTIONS.splice(index,1);
  updateDashboardMetrics();
  loadDashboardData();
  showToast(`Deleted transaction "${item.description}"`, 'success', 5000, () => {
    // undo callback
    MOCK_TRANSACTIONS.splice(lastDeleted.index,0,lastDeleted.item);
    lastDeleted = null;
    updateDashboardMetrics();
    loadDashboardData();
    showToast('Undo successful — transaction restored.');
  });
}

/* ----------------- Subscriptions CRUD (full) ----------------- */
function openSubscriptionModal() {
  document.getElementById('subscription-modal-title').textContent = 'Add Subscription';
  document.getElementById('subscription-form').reset();
  document.getElementById('subscription-edit-id').value = '';
  document.getElementById('subscription-modal').classList.remove('hidden');
}
function closeSubscriptionModal(event) {
  if (!event || event.target === document.getElementById('subscription-modal') || event.target.tagName === 'BUTTON') {
    document.getElementById('subscription-form').reset();
    document.getElementById('subscription-edit-id').value = '';
    document.getElementById('subscription-modal').classList.add('hidden');
  }
}
function addOrEditSubscription(e) {
  e.preventDefault();
  const id = document.getElementById('subscription-edit-id').value;
  const name = document.getElementById('subscription-name').value.trim();
  const amount = parseFloat(document.getElementById('subscription-amount').value);
  const frequency = document.getElementById('subscription-frequency').value;
  const category = document.getElementById('subscription-category').value.trim() || 'Other';
  const nextDue = document.getElementById('subscription-nextdue').value;
  if (!name || !amount || !frequency || !nextDue) { showToast('Fill all subscription fields','error'); return; }

  if (id) {
    const idx = MOCK_RECURRING_EXPENSES.findIndex(s => String(s.id) === String(id));
    if (idx !== -1) {
      MOCK_RECURRING_EXPENSES[idx] = { ...MOCK_RECURRING_EXPENSES[idx], name, amount, frequency, category, nextDue };
      showToast('Subscription updated.');
    } else showToast('Subscription not found', 'error');
  } else {
    const newId = (MOCK_RECURRING_EXPENSES.length ? Math.max(...MOCK_RECURRING_EXPENSES.map(r=>r.id)) : 0) + 1;
    MOCK_RECURRING_EXPENSES.push({ id: newId, name, amount, frequency, category, nextDue });
    showToast('Subscription added.');
  }
  closeSubscriptionModal();
  updateDashboardMetrics();
  loadRecurringExpenses();
}

function editSubscription(id) {
  const item = MOCK_RECURRING_EXPENSES.find(r => String(r.id) === String(id));
  if (!item) { showToast('Subscription not found','error'); return; }
  document.getElementById('subscription-edit-id').value = item.id;
  document.getElementById('subscription-name').value = item.name;
  document.getElementById('subscription-amount').value = item.amount;
  document.getElementById('subscription-frequency').value = item.frequency;
  document.getElementById('subscription-category').value = item.category;
  document.getElementById('subscription-nextdue').value = item.nextDue;
  document.getElementById('subscription-modal-title').textContent = 'Edit Subscription';
  document.getElementById('subscription-modal').classList.remove('hidden');
}

function deleteSubscription(id) {
  const item = MOCK_RECURRING_EXPENSES.find(r => String(r.id) === String(id));
  if (!item) { showToast('Subscription not found','error'); return; }
  const idx = MOCK_RECURRING_EXPENSES.findIndex(r => String(r.id) === String(id));
  lastDeleted = { type:'subscription', item: {...item}, index: idx };
  MOCK_RECURRING_EXPENSES.splice(idx,1);
  updateDashboardMetrics();
  loadRecurringExpenses();
  showToast(`Deleted subscription "${item.name}"`, 'success', 5000, () => {
    // undo
    MOCK_RECURRING_EXPENSES.splice(lastDeleted.index,0,lastDeleted.item);
    lastDeleted = null;
    updateDashboardMetrics();
    loadRecurringExpenses();
    showToast('Undo successful — subscription restored.');
  });
}

/* ----------------- Earnings CRUD (full) ----------------- */
function openAddEarningModal() {
  document.getElementById('earning-modal-title').textContent = 'Add Earning';
  document.getElementById('earning-form').reset();
  document.getElementById('earning-edit-id').value = '';
  document.getElementById('earning-modal').classList.remove('hidden');
}
function closeEarningModal(event) {
  if (!event || event.target === document.getElementById('earning-modal') || event.target.tagName === 'BUTTON') {
    document.getElementById('earning-form').reset();
    document.getElementById('earning-edit-id').value = '';
    document.getElementById('earning-modal').classList.add('hidden');
  }
}
function addOrEditEarning(e) {
  e.preventDefault();
  const id = document.getElementById('earning-edit-id').value;
  const source = document.getElementById('earning-source').value.trim();
  const amount = parseFloat(document.getElementById('earning-amount').value);
  if (!source || !amount) { showToast('Fill earning fields','error'); return; }
  if (id) {
    const idx = MOCK_EARNINGS.findIndex(it => String(it.id) === String(id));
    if (idx !== -1) {
      MOCK_EARNINGS[idx] = { ...MOCK_EARNINGS[idx], source, amount };
      showToast('Earning updated.');
    } else showToast('Earning not found','error');
  } else {
    const newId = (MOCK_EARNINGS.length ? Math.max(...MOCK_EARNINGS.map(e=>e.id)) : 0) + 1;
    MOCK_EARNINGS.push({ id: newId, source, amount });
    showToast('Earning added.');
  }
  closeEarningModal();
  updateDashboardMetrics();
  loadEarningsList();
}
function editEarning(id) {
  const item = MOCK_EARNINGS.find(e => String(e.id) === String(id));
  if (!item) { showToast('Earning not found','error'); return; }
  document.getElementById('earning-edit-id').value = item.id;
  document.getElementById('earning-source').value = item.source;
  document.getElementById('earning-amount').value = item.amount;
  document.getElementById('earning-modal-title').textContent = 'Edit Earning';
  document.getElementById('earning-modal').classList.remove('hidden');
}
function deleteEarning(id) {
  const item = MOCK_EARNINGS.find(e => String(e.id) === String(id));
  if (!item) { showToast('Earning not found','error'); return; }
  const idx = MOCK_EARNINGS.findIndex(e => String(e.id) === String(id));
  lastDeleted = { type:'earning', item: {...item}, index: idx };
  MOCK_EARNINGS.splice(idx,1);
  updateDashboardMetrics();
  loadEarningsList();
  showToast(`Deleted earning from "${item.source}"`, 'success', 5000, () => {
    MOCK_EARNINGS.splice(lastDeleted.index,0,lastDeleted.item);
    lastDeleted = null;
    updateDashboardMetrics();
    loadEarningsList();
    showToast('Undo successful — earning restored.');
  });
}

/* ----------------- Renderers ----------------- */
function getCategoryStyle(category) {
  switch (category) {
    case 'Rent/Utilities': return 'bg-blue-100 text-blue-800';
    case 'Social/Fun': return 'bg-yellow-100 text-yellow-800';
    case 'Groceries': return 'bg-green-100 text-green-800';
    case 'Recurring': return 'bg-purple-100 text-purple-800';
    case 'Textbooks/Supplies': return 'bg-red-100 text-red-800';
    case 'Transport': return 'bg-indigo-100 text-indigo-800';
    default: return 'bg-gray-100 text-gray-800';
  }
}

function loadDashboardData() {
  const list = document.getElementById('transactions-list');
  list.innerHTML = '';
  const recent = MOCK_TRANSACTIONS.slice().sort((a,b)=>new Date(b.date)-new Date(a.date)).slice(0,6);
  recent.forEach(t => {
    const row = document.createElement('tr');
    row.className = 'hover:bg-gray-50 transition duration-150';
    row.innerHTML = `
      <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-500">${t.date}</td>
      <td class="px-4 py-4 whitespace-nowrap text-sm font-medium text-gray-900">${t.description}</td>
      <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-500">
        <span class="px-3 py-1 inline-flex text-xs leading-5 font-semibold rounded-full ${getCategoryStyle(t.category)}">${t.category}</span>
      </td>
      <td class="px-4 py-4 whitespace-nowrap text-sm text-right font-bold text-gray-900">-₹${Number(t.amount).toFixed(2)}</td>
      <td class="px-4 py-4 whitespace-nowrap text-sm text-center">
        <button onclick="editExpense('${t.id}')" title="Edit" class="mr-2 inline-flex items-center px-2 py-1 rounded-md bg-gray-100 hover:bg-gray-200">
          <svg class="w-4 h-4 text-gray-700" viewBox="0 0 24 24" fill="none" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15.232 5.232l3.536 3.536M9 11l6-6 3 3-6 6H9v-3z"></path></svg>
        </button>
        <button onclick="deleteExpense('${t.id}')" title="Delete" class="inline-flex items-center px-2 py-1 rounded-md bg-red-100 hover:bg-red-200">
          <svg class="w-4 h-4 text-red-700" viewBox="0 0 24 24" fill="none" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>
        </button>
      </td>
    `;
    list.appendChild(row);
  });
}

function loadBudgetGoals() {
  const budgetList = document.getElementById('budgets-list');
  const goalsList = document.getElementById('goals-list');
  budgetList.innerHTML = '';
  goalsList.innerHTML = '';

  MOCK_BUDGETS.forEach(b => {
    const pct = b.limit ? (b.spent / b.limit) * 100 : 0;
    const statusColor = b.spent >= b.limit ? 'text-red-600 bg-red-100' : (pct >= 85 ? 'text-yellow-600 bg-yellow-100' : 'text-emerald-600 bg-emerald-100');
    const row = document.createElement('tr');
    row.className = 'hover:bg-gray-50 transition duration-150';
    row.innerHTML = `
      <td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">${b.category}</td>
      <td class="px-6 py-4 whitespace-nowrap text-sm text-right font-medium text-gray-700">₹${b.limit.toFixed(2)}</td>
      <td class="px-6 py-4 whitespace-nowrap text-sm text-right font-bold text-gray-900">₹${b.spent.toFixed(2)}</td>
      <td class="px-6 py-4 whitespace-nowrap text-sm text-center">
        <span class="px-3 py-1 inline-flex text-xs leading-5 font-semibold rounded-full ${statusColor}">${b.status} (${Math.round(pct)}%)</span>
      </td>
    `;
    budgetList.appendChild(row);
  });

  MOCK_GOALS.forEach(g => {
    const progress = g.target ? (g.saved / g.target) * 100 : 0;
    const goalCard = document.createElement('div');
    goalCard.className = 'p-4 border border-gray-200 rounded-xl shadow-sm hover:shadow-md transition duration-150';
    goalCard.innerHTML = `
      <h4 class="text-lg font-semibold text-gray-800">${g.name}</h4>
      <p class="text-sm text-gray-500 mt-1">Target: ₹${g.target.toFixed(0)} | Due: ${g.date}</p>
      <div class="mt-3">
        <div class="w-full bg-gray-200 rounded-full h-2.5">
          <div class="${progress >= 100 ? 'bg-emerald-500' : 'bg-blue-500'} h-2.5 rounded-full" style="width:${Math.min(100, progress).toFixed(0)}%;"></div>
        </div>
        <p class="text-sm font-medium mt-1 text-right text-gray-700">${progress.toFixed(1)}% complete (₹${g.saved.toFixed(0)} saved)</p>
      </div>
    `;
    goalsList.appendChild(goalCard);
  });

  const brief = document.getElementById('budgets-brief');
  if (brief) brief.innerHTML = MOCK_BUDGETS.map(b => `${b.category}: ₹${b.spent}/${b.limit}`).join('<br>');
}

function loadRecurringExpenses() {
  const recurringList = document.getElementById('recurring-list');
  recurringList.innerHTML = '';
  MOCK_RECURRING_EXPENSES.forEach(r => {
    const row = document.createElement('tr');
    row.className = 'hover:bg-gray-50 transition duration-150';
    row.innerHTML = `
      <td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">${r.name}</td>
      <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">${r.category}</td>
      <td class="px-6 py-4 whitespace-nowrap text-sm text-right font-bold text-red-600">-₹${r.amount.toFixed(2)}</td>
      <td class="px-6 py-4 whitespace-nowrap text-sm text-center">${r.frequency}</td>
      <td class="px-6 py-4 whitespace-nowrap text-sm text-center">${r.nextDue}</td>
      <td class="px-6 py-4 whitespace-nowrap text-sm text-center">
        <button onclick="editSubscription('${r.id}')" class="mr-2 inline-flex items-center px-2 py-1 rounded-md bg-gray-100 hover:bg-gray-200">Edit</button>
        <button onclick="deleteSubscription('${r.id}')" class="inline-flex items-center px-2 py-1 rounded-md bg-red-100 hover:bg-red-200">Delete</button>
      </td>
    `;
    recurringList.appendChild(row);
  });
}

function loadEarningsList() {
  const list = document.getElementById('earnings-list');
  list.innerHTML = '';
  MOCK_EARNINGS.forEach(e => {
    const row = document.createElement('tr');
    row.className = 'hover:bg-gray-50 transition duration-150';
    row.innerHTML = `
      <td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">${e.source}</td>
      <td class="px-6 py-4 whitespace-nowrap text-sm text-right font-bold text-emerald-700">₹${e.amount.toFixed(2)}</td>
      <td class="px-6 py-4 whitespace-nowrap text-sm text-center">
        <button onclick="editEarning('${e.id}')" class="mr-2 inline-flex items-center px-2 py-1 rounded-md bg-gray-100 hover:bg-gray-200">Edit</button>
        <button onclick="deleteEarning('${e.id}')" class="inline-flex items-center px-2 py-1 rounded-md bg-red-100 hover:bg-red-200">Delete</button>
      </td>
    `;
    list.appendChild(row);
  });
}

/* ----------------- Metrics & updates ----------------- */
function computeTotalExpenses() {
  return MOCK_TRANSACTIONS.reduce((s,t) => s + Number(t.amount || 0), 0);
}
function computeTotalIncome() {
  return MOCK_EARNINGS.reduce((s,e) => s + Number(e.amount || 0), 0);
}
function computeUpcomingBills(days=30) {
  const now = new Date();
  const horizon = new Date(now.getTime() + days*24*3600*1000);
  const upcoming = MOCK_RECURRING_EXPENSES.filter(r => new Date(r.nextDue) >= now && new Date(r.nextDue) <= horizon);
  const total = upcoming.reduce((s,r) => s + Number(r.amount || 0), 0);
  return { count: upcoming.length, total, items: upcoming };
}

function updateDashboardMetrics() {
  // recalc budgets spent from transactions
  const totals = MOCK_TRANSACTIONS.reduce((acc,t) => { acc[t.category] = (acc[t.category]||0) + Number(t.amount||0); return acc; }, {});
  MOCK_BUDGETS = MOCK_BUDGETS.map(b => ({ ...b, spent: totals[b.category] || 0, status: (totals[b.category]||0) >= b.limit ? 'Over' : 'Good' }));

  const expenses = computeTotalExpenses();
  const income = computeTotalIncome();
  const upcoming = computeUpcomingBills();
  const moneySpentEl = document.getElementById('money-spent-amount');
  if (moneySpentEl) moneySpentEl.textContent = `₹${expenses.toFixed(2)}`;
  const upcomingCountEl = document.getElementById('upcoming-bills-count');
  const upcomingSubEl = document.getElementById('upcoming-bills-sub');
  if (upcomingCountEl) upcomingCountEl.textContent = `${upcoming.count}`;
  if (upcomingSubEl) upcomingSubEl.textContent = `Totaling ₹${upcoming.total.toFixed(2)} in 30 days`;
  const totalIncomeEl = document.getElementById('total-income');
  const totalExpensesEl = document.getElementById('total-expenses');
  if (totalIncomeEl) totalIncomeEl.textContent = `₹${income.toFixed(2)}`;
  if (totalExpensesEl) totalExpensesEl.textContent = `₹${expenses.toFixed(2)}`;

  // repopulate lists
  loadDashboardData();
  loadBudgetGoals();
  loadRecurringExpenses();
  loadEarningsList();
}
/* --------- Budgets (Set New) --------- */
function openAddBudgetModal() {
  document.getElementById('budget-form').reset();
  document.getElementById('budget-edit-index').value = '';
  document.getElementById('budget-modal-title').textContent = 'Set New Budget';
  document.getElementById('budget-modal').classList.remove('hidden');
}
function closeBudgetModal(event) {
  if (!event || event.target === document.getElementById('budget-modal') || event.target.tagName === 'BUTTON') {
    document.getElementById('budget-form').reset();
    document.getElementById('budget-edit-index').value = '';
    document.getElementById('budget-modal').classList.add('hidden');
  }
}
function addOrEditBudget(e) {
  e.preventDefault();
  const idxStr = document.getElementById('budget-edit-index').value;
  const category = document.getElementById('budget-category').value.trim();
  const limit = parseFloat(document.getElementById('budget-limit').value) || 0;
  const spent = parseFloat(document.getElementById('budget-spent').value) || 0;
  if (!category) { showToast('Enter a category for the budget', 'error'); return; }

  if (idxStr) {
    const idx = parseInt(idxStr, 10);
    if (MOCK_BUDGETS[idx]) {
      MOCK_BUDGETS[idx] = { ...MOCK_BUDGETS[idx], category, limit, spent, status: spent >= limit ? 'Over' : 'Good' };
      showToast('Budget updated.');
    } else showToast('Budget index not found', 'error');
  } else {
    // if same category exists, update it instead of creating duplicate
    const existing = MOCK_BUDGETS.findIndex(b => b.category.toLowerCase() === category.toLowerCase());
    if (existing !== -1) {
      MOCK_BUDGETS[existing] = { ...MOCK_BUDGETS[existing], limit, spent, status: spent >= limit ? 'Over' : 'Good' };
      showToast('Existing budget updated.');
    } else {
      MOCK_BUDGETS.push({ category, limit, spent, status: spent >= limit ? 'Over' : 'Good' });
      showToast('Budget added.');
    }
  }

  closeBudgetModal();
  updateDashboardMetrics();
  loadBudgetGoals();
}

function editBudget(index) {
  const item = MOCK_BUDGETS[index];
  if (!item) { showToast('Budget not found', 'error'); return; }
  document.getElementById('budget-edit-index').value = index;
  document.getElementById('budget-category').value = item.category;
  document.getElementById('budget-limit').value = item.limit;
  document.getElementById('budget-spent').value = item.spent || 0;
  document.getElementById('budget-modal-title').textContent = 'Edit Budget';
  document.getElementById('budget-modal').classList.remove('hidden');
}

function deleteBudget(index) {
  const item = MOCK_BUDGETS[index];
  if (!item) { showToast('Budget not found', 'error'); return; }
  if (!confirm(`Delete budget for "${item.category}"?`)) return;
  MOCK_BUDGETS.splice(index, 1);
  showToast('Budget deleted.');
  updateDashboardMetrics();
  loadBudgetGoals();
}

/* --------- Goals (Add Goal) --------- */
function openAddGoalModal() {
  document.getElementById('goal-form').reset();
  document.getElementById('goal-edit-index').value = '';
  document.getElementById('goal-modal-title').textContent = 'Add Goal';
  document.getElementById('goal-modal').classList.remove('hidden');
}
function closeGoalModal(event) {
  if (!event || event.target === document.getElementById('goal-modal') || event.target.tagName === 'BUTTON') {
    document.getElementById('goal-form').reset();
    document.getElementById('goal-edit-index').value = '';
    document.getElementById('goal-modal').classList.add('hidden');
  }
}
function addOrEditGoal(e) {
  e.preventDefault();
  const idxStr = document.getElementById('goal-edit-index').value;
  const name = document.getElementById('goal-name').value.trim();
  const target = parseFloat(document.getElementById('goal-target').value) || 0;
  const saved = parseFloat(document.getElementById('goal-saved').value) || 0;
  const date = document.getElementById('goal-date').value;
  if (!name || !target || !date) { showToast('Please fill name, target and date', 'error'); return; }

  if (idxStr) {
    const idx = parseInt(idxStr, 10);
    if (MOCK_GOALS[idx]) {
      MOCK_GOALS[idx] = { ...MOCK_GOALS[idx], name, target, saved, date };
      showToast('Goal updated.');
    } else showToast('Goal index not found', 'error');
  } else {
    MOCK_GOALS.push({ name, target, saved, date });
    showToast('Goal added.');
  }

  closeGoalModal();
  updateDashboardMetrics();
  loadBudgetGoals();
}

function editGoal(index) {
  const g = MOCK_GOALS[index];
  if (!g) { showToast('Goal not found', 'error'); return; }
  document.getElementById('goal-edit-index').value = index;
  document.getElementById('goal-name').value = g.name;
  document.getElementById('goal-target').value = g.target;
  document.getElementById('goal-saved').value = g.saved || 0;
  document.getElementById('goal-date').value = g.date;
  document.getElementById('goal-modal-title').textContent = 'Edit Goal';
  document.getElementById('goal-modal').classList.remove('hidden');
}

function deleteGoal(index) {
  const g = MOCK_GOALS[index];
  if (!g) { showToast('Goal not found', 'error'); return; }
  if (!confirm(`Delete goal "${g.name}"?`)) return;
  MOCK_GOALS.splice(index, 1);
  showToast('Goal deleted.');
  updateDashboardMetrics();
  loadBudgetGoals();
}

/* --------- Hook small UI pieces to show edit/delete in the rendered lists --------- */
/* Note: This wiring assumes loadBudgetGoals() renders a list you can augment.
   We will replace budgets and goals rendering to include edit/delete buttons. */

function loadBudgetGoals() {
  // re-use the existing renderer (override to inject actions)
  const budgetList = document.getElementById('budgets-list');
  const goalsList = document.getElementById('goals-list');
  if (!budgetList || !goalsList) return;

  budgetList.innerHTML = '';
  goalsList.innerHTML = '';

  MOCK_BUDGETS.forEach((b, idx) => {
    const pct = b.limit ? (b.spent / b.limit) * 100 : 0;
    const statusColor = b.spent >= b.limit ? 'text-red-600 bg-red-100' : (pct >= 85 ? 'text-yellow-600 bg-yellow-100' : 'text-emerald-600 bg-emerald-100');
    const row = document.createElement('tr');
    row.className = 'hover:bg-gray-50 transition duration-150';
    row.innerHTML = `
      <td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">${b.category}</td>
      <td class="px-6 py-4 whitespace-nowrap text-sm text-right font-medium text-gray-700">₹${Number(b.limit).toFixed(2)}</td>
      <td class="px-6 py-4 whitespace-nowrap text-sm text-right font-bold text-gray-900">₹${Number(b.spent).toFixed(2)}</td>
      <td class="px-6 py-4 whitespace-nowrap text-sm text-center">
        <span class="px-3 py-1 inline-flex text-xs leading-5 font-semibold rounded-full ${statusColor}">${b.status || 'Good'} (${Math.round(pct)}%)</span>
        <div class="mt-2 space-x-2">
          <button onclick="editBudget(${idx})" class="inline-flex items-center px-2 py-1 rounded-md bg-gray-100 hover:bg-gray-200 text-xs">Edit</button>
          <button onclick="deleteBudget(${idx})" class="inline-flex items-center px-2 py-1 rounded-md bg-red-100 hover:bg-red-200 text-xs">Delete</button>
        </div>
      </td>
    `;
    budgetList.appendChild(row);
  });

  MOCK_GOALS.forEach((g, idx) => {
    const progress = g.target ? (g.saved / g.target) * 100 : 0;
    const goalCard = document.createElement('div');
    goalCard.className = 'p-4 border border-gray-200 rounded-xl shadow-sm hover:shadow-md transition duration-150 relative';
    goalCard.innerHTML = `
      <h4 class="text-lg font-semibold text-gray-800">${g.name}</h4>
      <p class="text-sm text-gray-500 mt-1">Target: ₹${Number(g.target).toFixed(0)} | Due: ${g.date}</p>
      <div class="mt-3">
        <div class="w-full bg-gray-200 rounded-full h-2.5">
          <div class="${progress >= 100 ? 'bg-emerald-500' : 'bg-blue-500'} h-2.5 rounded-full" style="width:${Math.min(100, progress).toFixed(0)}%;"></div>
        </div>
        <p class="text-sm font-medium mt-1 text-right text-gray-700">${progress.toFixed(1)}% complete (₹${Number(g.saved).toFixed(0)} saved)</p>
      </div>
      <div class="absolute top-3 right-3 space-x-2">
        <button onclick="editGoal(${idx})" class="inline-flex items-center px-2 py-1 rounded-md bg-gray-100 hover:bg-gray-200 text-xs">Edit</button>
        <button onclick="deleteGoal(${idx})" class="inline-flex items-center px-2 py-1 rounded-md bg-red-100 hover:bg-red-200 text-xs">Delete</button>
      </div>
    `;
    goalsList.appendChild(goalCard);
  });
}

/* ----------------- Wiring on load ----------------- */
document.addEventListener('DOMContentLoaded', () => {
  // auth form
  const authForm = document.getElementById('auth-form');
  if (authForm) authForm.addEventListener('submit', (e) => {
    e.preventDefault();
    const email = document.getElementById('auth-email').value.trim();
    const password = document.getElementById('auth-password').value;
    if (!email || !password) { showToast('Enter email & password','error'); return; }
    mockSignInDirect(email);
  });

  document.getElementById('use-mock-btn').addEventListener('click', (e) => {
    e.preventDefault();
    const em = document.getElementById('auth-email').value.trim();
    const pw = document.getElementById('auth-password').value;
    if (!em || !pw) {
      document.getElementById('auth-email').value = 'mockuser@example.com';
      document.getElementById('auth-password').value = 'test1234';
      showToast('Prefilled mock credentials. Click Use Mock again to sign in.');
      return;
    }
    mockSignInDirect(em);
  });

  document.querySelectorAll('.guest-link').forEach(a => a.addEventListener('click', (ev)=>{ ev.preventDefault(); useGuestMode(); }));

  // modals: click outside to close
  document.getElementById('add-expense-modal').addEventListener('click', (e)=> { if (e.target === document.getElementById('add-expense-modal')) closeAddExpenseModal(e); });
  document.getElementById('subscription-modal').addEventListener('click', (e)=> { if (e.target === document.getElementById('subscription-modal')) closeSubscriptionModal(e); });
  document.getElementById('earning-modal').addEventListener('click', (e)=> { if (e.target === document.getElementById('earning-modal')) closeEarningModal(e); });

  // initial UI
  showLoginForm();
});

/* Expose functions for inline onclick handlers */
window.openAddExpenseModal = openAddExpenseModal;
window.closeAddExpenseModal = closeAddExpenseModal;
window.addOrEditExpense = addOrEditExpense;
window.editExpense = editExpense;
window.deleteExpense = deleteExpense;

window.openSubscriptionModal = openSubscriptionModal;
window.closeSubscriptionModal = closeSubscriptionModal;
window.addOrEditSubscription = addOrEditSubscription;
window.editSubscription = editSubscription;
window.deleteSubscription = deleteSubscription;

window.openAddEarningModal = openAddEarningModal;
window.closeEarningModal = closeEarningModal;
window.addOrEditEarning = addOrEditEarning;
window.editEarning = editEarning;
window.deleteEarning = deleteEarning;

window.showDashboard = showDashboard;
window.showBudget = showBudget;
window.showRecurring = showRecurring;
window.showMoney = showMoney;
window.showAIInsight = showAIInsight;
window.showCoverView = showCoverView;
window.continueToApp = continueToApp;
window.showAppView = showAppView;
window.showLoginForm = showLoginForm;
window.showSignupForm = showSignupForm;
window.mockSignInDirect = mockSignInDirect;
window.useGuestMode = useGuestMode;
window.handleSignOut = handleSignOut;

</script>
</body>
</html>
