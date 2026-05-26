// Cache for github repositories list
let githubRepos = [];
let detectedStackInfo = null;

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
    checkSettings();
    loadLastVPSConnection();
    setupPrivateKeyMasking('private_key');
    setupPrivateKeyMasking('deploy_private_key');
});

function toggleAuthFields() {
    const authMethod = document.getElementById('auth_method').value;
    const passwordGroup = document.getElementById('password-group');
    const keyGroup = document.getElementById('key-group');

    if (authMethod === 'password') {
        passwordGroup.classList.remove('hidden');
        keyGroup.classList.add('hidden');
    } else {
        passwordGroup.classList.add('hidden');
        keyGroup.classList.remove('hidden');
    }
}

function toggleDeployAuthFields() {
    const authMethod = document.getElementById('deploy_auth_method').value;
    const passwordGroup = document.getElementById('deploy-password-group');
    const keyGroup = document.getElementById('deploy-key-group');

    if (authMethod === 'password') {
        passwordGroup.classList.remove('hidden');
        keyGroup.classList.add('hidden');
    } else {
        passwordGroup.classList.add('hidden');
        keyGroup.classList.remove('hidden');
    }
}

// Check Settings status from Go Backend
async function checkSettings() {
    updateGitHubIndicator('checking');
    try {
        const response = await fetch('/api/v1/settings/github');
        const settings = await response.json();

        const banner = document.getElementById('github-unconfigured-banner');
        const oauthPrompt = document.getElementById('github-oauth-prompt');

        if (!settings.configured) {
            banner.classList.remove('hidden');
            oauthPrompt.classList.add('hidden');
            updateGitHubIndicator('unconfigured');
            githubRepos = [];
            return;
        }

        banner.classList.add('hidden');
        
        // Settings configured, now check if logged in
        await checkGitHubLogin();
    } catch (err) {
        console.error('Failed to verify backend settings status:', err);
        updateGitHubIndicator('error');
    }
}

async function checkGitHubLogin() {
    const oauthPrompt = document.getElementById('github-oauth-prompt');
    try {
        const userResponse = await fetch('/api/v1/github/user');
        if (userResponse.status === 401) {
            oauthPrompt.classList.remove('hidden');
            updateGitHubIndicator('unauthorized');
            githubRepos = [];
            return;
        }

        if (!userResponse.ok) {
            throw new Error('Failed to get profile');
        }

        const user = await userResponse.json();
        oauthPrompt.classList.add('hidden');
        updateGitHubIndicator('connected', user.login);

        // Fetch repo list for autocomplete cache
        const reposResponse = await fetch('/api/v1/github/repos');
        if (reposResponse.ok) {
            githubRepos = await reposResponse.json();
        }
    } catch (err) {
        console.error('Failed to list repos:', err);
        oauthPrompt.classList.remove('hidden');
        updateGitHubIndicator('unauthorized');
    }
}

function updateGitHubIndicator(state, username = '') {
    const dot = document.getElementById('github-status-dot');
    const text = document.getElementById('github-status-text');
    const discBtn = document.getElementById('github-disconnect-btn');
    if (!dot || !text) return;

    dot.className = 'w-2 h-2 rounded-full transition-all duration-300';
    if (discBtn) discBtn.classList.add('hidden');
    
    if (state === 'checking') {
        dot.classList.add('bg-slate-500', 'animate-pulse');
        text.textContent = 'Checking GitHub Connection...';
    } else if (state === 'unconfigured') {
        dot.classList.add('bg-rose-500', 'animate-pulse');
        text.textContent = 'GitHub Disconnected (Credentials Missing)';
    } else if (state === 'unauthorized') {
        dot.classList.add('bg-amber-500', 'animate-pulse');
        text.textContent = 'GitHub Configured (Authorization Required)';
    } else if (state === 'connected') {
        dot.classList.add('bg-emerald-500', 'shadow-[0_0_8px_rgba(16,185,129,0.7)]');
        text.innerHTML = `Connected to GitHub as <span class="text-emerald-400 font-semibold">@${username}</span>`;
        if (discBtn) discBtn.classList.remove('hidden');
    } else {
        dot.classList.add('bg-slate-500');
        text.textContent = 'GitHub connection error';
    }
}

async function loadLastVPSConnection() {
    try {
        const response = await fetch('/api/v1/vps/last-connection');
        if (!response.ok) return;
        const data = await response.json();
        
        if (data.ip_address) {
            document.getElementById('ip_address').value = data.ip_address;
            document.getElementById('ssh_port').value = data.ssh_port;
            document.getElementById('ssh_user').value = data.ssh_user;
            document.getElementById('auth_method').value = data.auth_method || 'password';
            document.getElementById('password').value = data.password || '';
            setPrivateKeyVal('private_key', data.private_key || '');
            toggleAuthFields();

            // Also auto-populate deploy form
            document.getElementById('deploy_ip').value = data.ip_address;
            document.getElementById('deploy_port').value = data.ssh_port;
            document.getElementById('deploy_user').value = data.ssh_user;
            document.getElementById('deploy_auth_method').value = data.auth_method || 'password';
            document.getElementById('deploy_password').value = data.password || '';
            setPrivateKeyVal('deploy_private_key', data.private_key || '');
            toggleDeployAuthFields();
        }
    } catch (err) {
        console.error('Failed to load last connection:', err);
    }
}

// Save GitHub integration details
async function saveSettings() {
    const clientId = document.getElementById('settings_client_id').value.trim();
    const clientSecret = document.getElementById('settings_client_secret').value.trim();

    try {
        const response = await fetch('/api/v1/settings/github', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ client_id: clientId, client_secret: clientSecret })
        });

        const result = await response.json();
        if (!response.ok) {
            throw new Error(result.error || 'Failed to save settings');
        }

        showToast('GitHub configuration updated successfully!', 'success');
        toggleSettingsModal(false);
        checkSettings();
    } catch (err) {
        showToast('Settings error: ' + err.message, 'error');
    }
}

function toggleSettingsModal(show) {
    const modal = document.getElementById('settings-modal');
    if (show) {
        modal.classList.remove('hidden');
    } else {
        modal.classList.add('hidden');
    }
}

// Search repositories autocomplete
function searchRepos(query) {
    const container = document.getElementById('repo-autocomplete');
    if (!query) {
        container.classList.add('hidden');
        return;
    }

    const matches = githubRepos.filter(r => r.full_name.toLowerCase().includes(query.toLowerCase()));
    if (matches.length === 0) {
        container.classList.add('hidden');
        return;
    }

    container.innerHTML = '';
    matches.forEach(repo => {
        const div = document.createElement('div');
        div.className = 'px-4 py-3 hover:bg-white/5 cursor-pointer text-slate-200 text-xs border-b border-white/5 last:border-b-0 transition-colors';
        div.textContent = repo.full_name;
        div.onclick = () => selectRepo(repo);
        container.appendChild(div);
    });

    container.classList.remove('hidden');
}

function selectRepo(repo) {
    document.getElementById('github_repo').value = repo.full_name;
    document.getElementById('repo-autocomplete').classList.add('hidden');
    
    // Auto-populate deployment project fields
    const repoName = repo.full_name.split('/')[1] || '';
    document.getElementById('deploy_project_name').value = repoName;
    document.getElementById('deploy_path').value = `/var/www/${repoName}`;

    // Load branches for this repo
    fetchBranches(repo.full_name, repo.default_branch || 'main');

    // Auto-detect stack on repository selection
    detectStack();
}

async function probeVPS() {
    const ip = document.getElementById('ip_address').value.trim();
    const port = parseInt(document.getElementById('ssh_port').value, 10);
    const user = document.getElementById('ssh_user').value.trim();
    const authMethod = document.getElementById('auth_method').value;
    const password = document.getElementById('password').value;
    const privateKey = getPrivateKeyVal('private_key');

    if (!ip || !user) {
        showToast('Please enter VPS Host IP and SSH Username', 'warning');
        return;
    }

    const btn = document.querySelector('#vps-form button');
    const spinner = document.getElementById('vps-spinner');
    const diagBox = document.getElementById('vps-diagnostics');

    btn.disabled = true;
    spinner.classList.remove('hidden');
    diagBox.classList.remove('hidden');

    updateField('vps-status-connected', 'Checking...', 'px-2.5 py-0.5 rounded-full text-xs font-semibold uppercase bg-amber-500/10 text-amber-400 border border-amber-500/25');
    updateField('vps-status-os', 'Checking...', 'font-semibold text-slate-400');
    updateField('vps-status-docker', 'Checking...', 'font-semibold text-slate-400');
    updateField('vps-status-compose', 'Checking...', 'font-semibold text-slate-400');
    updateField('vps-status-sudo', 'Checking...', 'font-semibold text-slate-400');
    updateField('vps-status-group', 'Checking...', 'font-semibold text-slate-400');

    try {
        const payload = {
            ip_address: ip,
            ssh_port: port,
            ssh_user: user,
            auth_method: authMethod
        };

        if (authMethod === 'password') {
            payload.password = password;
        } else {
            payload.private_key = privateKey;
        }

        const response = await fetch('/api/v1/vps/probe', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        const result = await response.json();
        if (!response.ok) {
            throw new Error(result.error || 'Server returned an error');
        }

        if (result.connected) {
            updateField('vps-status-connected', 'Connected', 'px-2.5 py-0.5 rounded-full text-xs font-semibold uppercase bg-emerald-500/10 text-emerald-400 border border-emerald-500/25');
            updateField('vps-status-os', result.os || 'Linux', 'font-semibold text-slate-200');
            
            const docVer = result.docker_version;
            updateField('vps-status-docker', docVer, docVer.startsWith('Docker') ? 'font-semibold text-emerald-400' : 'font-semibold text-rose-400');

            const compVer = result.compose_version;
            updateField('vps-status-compose', compVer, compVer.startsWith('Docker') ? 'font-semibold text-emerald-400' : 'font-semibold text-rose-400');

            updateField('vps-status-sudo', result.has_sudo ? 'Granted' : 'Denied', result.has_sudo ? 'font-semibold text-emerald-400' : 'font-semibold text-rose-400');
            updateField('vps-status-group', result.in_docker_group ? 'Yes' : 'No', result.in_docker_group ? 'font-semibold text-emerald-400' : 'font-semibold text-rose-400');
            showToast('VPS Connection & Diagnostics successfully completed!', 'success');
        } else {
            updateField('vps-status-connected', 'Failed', 'px-2.5 py-0.5 rounded-full text-xs font-semibold uppercase bg-rose-500/10 text-rose-400 border border-rose-500/25');
            updateField('vps-status-os', '-', 'font-semibold text-slate-400');
            updateField('vps-status-docker', '-', 'font-semibold text-slate-400');
            updateField('vps-status-compose', '-', 'font-semibold text-slate-400');
            updateField('vps-status-sudo', '-', 'font-semibold text-slate-400');
            updateField('vps-status-group', '-', 'font-semibold text-slate-400');
            showToast('Connection failed: ' + (result.error || 'Unreachable'), 'error');
        }
    } catch (err) {
        showToast('Error: ' + err.message, 'error');
        updateField('vps-status-connected', 'Error', 'px-2.5 py-0.5 rounded-full text-xs font-semibold uppercase bg-rose-500/10 text-rose-400 border border-rose-500/25');
    } finally {
        btn.disabled = false;
        spinner.classList.add('hidden');
    }
}

async function detectStack() {
    const repo = document.getElementById('github_repo').value.trim();
    const token = document.getElementById('github_token').value.trim();

    if (!repo) {
        showToast('Please select a GitHub repository', 'warning');
        return;
    }

    const btn = document.querySelector('#github-form button');
    const spinner = document.getElementById('git-spinner');
    const diagBox = document.getElementById('git-diagnostics');

    btn.disabled = true;
    spinner.classList.remove('hidden');
    diagBox.classList.remove('hidden');

    try {
        const response = await fetch('/api/v1/projects/detect-stack', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ repo, token })
        });

        const result = await response.json();
        if (!response.ok) {
            throw new Error(result.error || 'Failed to detect stack');
        }

        detectedStackInfo = result;

        const logo = document.getElementById('tech-logo-char');
        logo.className = 'w-12 h-12 rounded-xl bg-white/[0.03] border border-white/5 flex items-center justify-center text-lg font-bold transition-colors'; 

        let logoChar = '?';
        if (result.language === 'go') {
            logoChar = 'Go';
            logo.classList.add('bg-blue-500/10', 'border-blue-500/20', 'text-blue-400');
        } else if (result.language === 'node') {
            logoChar = 'JS';
            logo.classList.add('bg-emerald-500/10', 'border-emerald-500/20', 'text-emerald-400');
        } else if (result.language === 'python') {
            logoChar = 'Py';
            logo.classList.add('bg-yellow-500/10', 'border-yellow-500/20', 'text-yellow-400');
        }

        logo.textContent = logoChar;
        document.getElementById('tech-language').textContent = result.language;
        document.getElementById('tech-version').textContent = 'Base Tag: ' + result.version;
        document.getElementById('tech-port').textContent = result.default_port;
        document.getElementById('tech-files').textContent = result.detected_files.join(', ') || 'None';

        // Auto-fill deploy page properties
        document.getElementById('deploy_stack_info').value = `${result.language} (version ${result.version})`;
        document.getElementById('deploy_port_val').value = result.default_port;

        const repoParts = repo.split('/');
        const repoName = repoParts[repoParts.length - 1];
        if (repoName) {
            document.getElementById('deploy_project_name').value = repoName;
            document.getElementById('deploy_path').value = `/var/www/${repoName}`;
        }

        // Fetch branches for manually entered repos
        fetchBranches(repo);

        showToast('Stack Discovery successfully completed!', 'success');
    } catch (err) {
        showToast('Detection error: ' + err.message, 'error');
        document.getElementById('tech-language').textContent = 'Unknown';
        document.getElementById('tech-version').textContent = 'Version: -';
        document.getElementById('tech-port').textContent = '-';
        document.getElementById('tech-files').textContent = '-';
        const logo = document.getElementById('tech-logo-char');
        logo.className = 'w-12 h-12 rounded-xl bg-white/[0.03] border border-white/5 flex items-center justify-center text-lg font-bold transition-colors';
        logo.textContent = '?';
    } finally {
        btn.disabled = false;
        spinner.classList.add('hidden');
    }
}

// Copy connection credential fields from probe to deploy form
function copyVPSDetails() {
    document.getElementById('deploy_ip').value = document.getElementById('ip_address').value;
    document.getElementById('deploy_port').value = document.getElementById('ssh_port').value;
    document.getElementById('deploy_user').value = document.getElementById('ssh_user').value;
    
    const authMethod = document.getElementById('auth_method').value;
    document.getElementById('deploy_auth_method').value = authMethod;
    toggleDeployAuthFields();

    if (authMethod === 'password') {
        document.getElementById('deploy_password').value = document.getElementById('password').value;
    } else {
        setPrivateKeyVal('deploy_private_key', getPrivateKeyVal('private_key'));
    }

    showToast('Credentials copied successfully!', 'success');
}

// Trigger Deploy POST to setup backend CI/CD integration
async function triggerDeploy() {
    const payload = {
        ip_address: document.getElementById('deploy_ip').value.trim(),
        ssh_port: parseInt(document.getElementById('deploy_port').value, 10),
        ssh_user: document.getElementById('deploy_user').value.trim(),
        auth_method: document.getElementById('deploy_auth_method').value,
        github_repo: document.getElementById('github_repo').value.trim(),
        github_branch: document.getElementById('deploy_branch').value.trim(),
        project_name: document.getElementById('deploy_project_name').value.trim(),
        deployment_path: document.getElementById('deploy_path').value.trim(),
        app_port: parseInt(document.getElementById('deploy_port_val').value, 10),
        github_token: document.getElementById('github_token').value.trim(),
    };

    if (payload.auth_method === 'password') {
        payload.password = document.getElementById('deploy_password').value;
    } else {
        payload.private_key = getPrivateKeyVal('deploy_private_key');
    }

    if (detectedStackInfo) {
        payload.stack_type = detectedStackInfo.language;
        payload.stack_version = detectedStackInfo.version;
    } else {
        payload.stack_type = 'unknown';
        payload.stack_version = 'latest';
    }

    const btn = document.querySelector('#deploy-form button');
    const spinner = document.getElementById('deploy-spinner');

    btn.disabled = true;
    spinner.classList.remove('hidden');

    try {
        const response = await fetch('/api/v1/projects/deploy', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        const result = await response.json();
        if (!response.ok) {
            throw new Error(result.error || 'Failed to deploy project');
        }

        showToast('Deployment configured & auto CI/CD setup success!', 'success');
    } catch (err) {
        showToast('Deployment failed: ' + err.message, 'error');
    } finally {
        btn.disabled = false;
        spinner.classList.add('hidden');
    }
}

function updateField(elementId, value, extraClass = '') {
    const el = document.getElementById(elementId);
    if (!el) return;
    const valSpan = el.querySelector('.val');
    if (valSpan) {
        valSpan.textContent = value;
        if (extraClass) {
            valSpan.className = 'val ' + extraClass;
        }
    }
}

function showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');
    toast.className = 'bg-slate-900 border border-white/5 border-l-4 rounded-xl px-5 py-3.5 text-slate-200 text-sm shadow-2xl backdrop-blur-md min-w-[300px] flex items-center justify-between transition-all duration-300 transform translate-y-2 opacity-0';
    
    if (type === 'success') {
        toast.classList.add('border-l-emerald-500');
    } else if (type === 'error') {
        toast.classList.add('border-l-rose-500');
    } else if (type === 'warning') {
        toast.classList.add('border-l-amber-500');
    } else {
        toast.classList.add('border-l-blue-500');
    }

    toast.textContent = message;
    container.appendChild(toast);

    setTimeout(() => {
        toast.classList.remove('translate-y-2', 'opacity-0');
        toast.classList.add('translate-y-0', 'opacity-100');
    }, 10);

    setTimeout(() => {
        toast.classList.remove('translate-y-0', 'opacity-100');
        toast.classList.add('translate-y-[-10px]', 'opacity-0');
        toast.addEventListener('transitionend', () => {
            toast.remove();
        });
    }, 4000);
}

async function saveVPSConnectionManual() {
    const payload = {
        ip_address: document.getElementById('ip_address').value.trim(),
        ssh_port: parseInt(document.getElementById('ssh_port').value, 10) || 22,
        ssh_user: document.getElementById('ssh_user').value.trim(),
        auth_method: document.getElementById('auth_method').value,
        password: document.getElementById('password').value,
        private_key: getPrivateKeyVal('private_key'),
    };

    if (!payload.ip_address || !payload.ssh_user) {
        showToast('IP Address and SSH User are required to save credentials', 'warning');
        return;
    }

    try {
        const response = await fetch('/api/v1/vps/last-connection', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        const result = await response.json();
        if (!response.ok) {
            throw new Error(result.error || 'Failed to save connection credentials');
        }

        showToast('VPS credentials saved successfully!', 'success');

        // Populate deploy form too
        document.getElementById('deploy_ip').value = payload.ip_address;
        document.getElementById('deploy_port').value = payload.ssh_port;
        document.getElementById('deploy_user').value = payload.ssh_user;
        document.getElementById('deploy_auth_method').value = payload.auth_method;
        document.getElementById('deploy_password').value = payload.password;
        setPrivateKeyVal('deploy_private_key', payload.private_key);
        toggleDeployAuthFields();
    } catch (err) {
        showToast(err.message, 'error');
    }
}

async function disconnectGitHub() {
    if (!confirm('Are you sure you want to disconnect your GitHub integration? This will clear your access token.')) {
        return;
    }

    try {
        const response = await fetch('/api/v1/github/disconnect', {
            method: 'POST'
        });

        const result = await response.json();
        if (!response.ok) {
            throw new Error(result.error || 'Failed to disconnect from GitHub');
        }

        showToast('Successfully disconnected from GitHub!', 'success');
        
        // Hide disconnect button and trigger settings refresh
        const discBtn = document.getElementById('github-disconnect-btn');
        if (discBtn) discBtn.classList.add('hidden');

        githubRepos = [];
        const container = document.getElementById('repo-autocomplete');
        if (container) {
            container.innerHTML = '';
            container.classList.add('hidden');
        }

        await checkSettings();
    } catch (err) {
        showToast(err.message, 'error');
    }
}

async function fetchBranches(repo, defaultBranch = 'main') {
    if (!repo) return;
    try {
        const response = await fetch(`/api/v1/github/branches?repo=${encodeURIComponent(repo)}`);
        if (!response.ok) {
            throw new Error('Failed to fetch branches');
        }
        const branches = await response.json();
        const select = document.getElementById('deploy_branch');
        if (!select) return;
        
        select.innerHTML = '';
        branches.forEach(b => {
            const opt = document.createElement('option');
            opt.value = b.name;
            opt.textContent = b.name;
            select.appendChild(opt);
        });

        // Try to select defaultBranch if it exists in the list
        const hasDefault = branches.some(b => b.name === defaultBranch);
        if (hasDefault) {
            select.value = defaultBranch;
        } else if (branches.length > 0) {
            select.value = branches[0].name;
        }
    } catch (err) {
        console.error('Failed to load branches:', err);
    }
}

async function fetchBranches(repo, defaultBranch = 'main') {
    if (!repo) return;
    const token = document.getElementById('github_token').value.trim();
    try {
        let url = `/api/v1/github/branches?repo=${encodeURIComponent(repo)}`;
        if (token) {
            url += `&token=${encodeURIComponent(token)}`;
        }
        const response = await fetch(url);
        if (!response.ok) {
            throw new Error('Failed to fetch branches');
        }
        const branches = await response.json();
        const select = document.getElementById('deploy_branch');
        if (!select) return;
        
        select.innerHTML = '';
        branches.forEach(b => {
            const opt = document.createElement('option');
            opt.value = b.name;
            opt.textContent = b.name;
            select.appendChild(opt);
        });

        // Try to select defaultBranch if it exists in the list
        const hasDefault = branches.some(b => b.name === defaultBranch);
        if (hasDefault) {
            select.value = defaultBranch;
        } else if (branches.length > 0) {
            select.value = branches[0].name;
        }
    } catch (err) {
        console.error('Failed to load branches:', err);
    }
}

function setupPrivateKeyMasking(elementId) {
    const el = document.getElementById(elementId);
    if (!el) return;

    el._actualValue = el.value || '';

    el.addEventListener('focus', () => {
        el.value = el._actualValue || '';
    });

    el.addEventListener('blur', () => {
        el._actualValue = el.value || '';
        if (el.value.trim() !== '') {
            el.value = '★'.repeat(64) + '\n[SSH Private Key Masked for Security]';
        }
    });

    el.addEventListener('input', () => {
        el._actualValue = el.value || '';
    });
}

function getPrivateKeyVal(elementId) {
    const el = document.getElementById(elementId);
    if (!el) return '';
    return el._actualValue !== undefined ? el._actualValue : el.value;
}

function setPrivateKeyVal(elementId, val) {
    const el = document.getElementById(elementId);
    if (!el) return;
    el._actualValue = val || '';
    if (document.activeElement === el) {
        el.value = el._actualValue;
    } else {
        if (el._actualValue.trim() !== '') {
            el.value = '★'.repeat(64) + '\n[SSH Private Key Masked for Security]';
        } else {
            el.value = '';
        }
    }
}
