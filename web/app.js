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

async function probeVPS() {
    const ip = document.getElementById('ip_address').value.trim();
    const port = parseInt(document.getElementById('ssh_port').value, 10);
    const user = document.getElementById('ssh_user').value.trim();
    const authMethod = document.getElementById('auth_method').value;
    const password = document.getElementById('password').value;
    const privateKey = document.getElementById('private_key').value;

    if (!ip || !user) {
        showToast('Please enter VPS Host IP and SSH Username', 'warning');
        return;
    }

    // Set Loading State
    const btn = document.querySelector('#vps-form button');
    const spinner = document.getElementById('vps-spinner');
    const diagBox = document.getElementById('vps-diagnostics');

    btn.disabled = true;
    spinner.classList.remove('hidden');
    diagBox.classList.remove('hidden');

    // Reset UI fields to checking state with Tailwind badges
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

        // Render response data with Tailwind styling
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
        showToast('Please enter a GitHub repository (username/repo)', 'warning');
        return;
    }

    // Set Loading State
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

        // Render tech stack logo and properties using Tailwind CSS classes
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
    
    // Core Tailwind Toast classes
    toast.className = 'bg-slate-900 border border-white/5 border-l-4 rounded-xl px-5 py-3.5 text-slate-200 text-sm shadow-2xl backdrop-blur-md min-w-[300px] flex items-center justify-between transition-all duration-300 transform translate-y-2 opacity-0';
    
    // Custom borders
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

    // Trigger visual entry transition
    setTimeout(() => {
        toast.classList.remove('translate-y-2', 'opacity-0');
        toast.classList.add('translate-y-0', 'opacity-100');
    }, 10);

    // Auto-remove after 4 seconds
    setTimeout(() => {
        toast.classList.remove('translate-y-0', 'opacity-100');
        toast.classList.add('translate-y-[-10px]', 'opacity-0');
        toast.addEventListener('transitionend', () => {
            toast.remove();
        });
    }, 4000);
}
