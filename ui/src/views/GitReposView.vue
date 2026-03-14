<script setup lang="ts">
import { onMounted, ref, computed } from 'vue'
import DataTable from 'primevue/datatable'
import Column from 'primevue/column'
import Button from 'primevue/button'
import Drawer from 'primevue/drawer'
import InputText from 'primevue/inputtext'
import Select from 'primevue/select'
import Textarea from 'primevue/textarea'
import Skeleton from 'primevue/skeleton'
import Tag from 'primevue/tag'
import ToggleSwitch from 'primevue/toggleswitch'
import PageHeader from '../components/shared/PageHeader.vue'
import EmptyState from '../components/shared/EmptyState.vue'
import { useCrud } from '../composables/useCrud'
import { useConfirmAction } from '../composables/useConfirm'
import { useRole } from '../composables/useRole'
import { useNotificationStore } from '../stores/notification'
import * as gitRepoApi from '../api/gitRepos'
import type { GitRepo, GitRepoCreate, GitRepoUpdate } from '../types'

const { isAdmin } = useRole()
const { confirmDelete } = useConfirmAction()
const notifications = useNotificationStore()

const { items: repos, loading, fetch: fetchRepos, create, update, remove } = useCrud<
  GitRepo,
  GitRepoCreate,
  GitRepoUpdate
>(
  {
    list: gitRepoApi.listGitRepos,
    create: gitRepoApi.createGitRepo,
    update: (id: number, data: GitRepoUpdate) => gitRepoApi.updateGitRepo(id, data),
    remove: gitRepoApi.deleteGitRepo,
  },
  'Git Repository',
)

const drawerVisible = ref(false)
const editingId = ref<number | null>(null)
const testingId = ref<number | null>(null)
const syncingId = ref<number | null>(null)

const form = ref({
  name: '',
  remote_url: '',
  auth_type: 'none' as 'ssh' | 'https' | 'none',
  credentials: '',
  default_branch: 'main',
  local_path: '',
  known_hosts: '',
  is_enabled: true,
})

const authTypeOptions = [
  { label: 'None', value: 'none' },
  { label: 'SSH Key', value: 'ssh' },
  { label: 'HTTPS (PAT)', value: 'https' },
]

const showCredentials = computed(() => form.value.auth_type !== 'none')
const credentialsLabel = computed(() =>
  form.value.auth_type === 'ssh' ? 'SSH Private Key (PEM)' : 'Personal Access Token',
)
const credentialsPlaceholder = computed(() =>
  form.value.auth_type === 'ssh'
    ? '-----BEGIN OPENSSH PRIVATE KEY-----\n...'
    : 'ghp_xxxxxxxxxxxx',
)

function openCreate() {
  editingId.value = null
  form.value = {
    name: '',
    remote_url: '',
    auth_type: 'none',
    credentials: '',
    default_branch: 'main',
    local_path: '',
    known_hosts: '',
    is_enabled: true,
  }
  drawerVisible.value = true
}

async function openEdit(repo: GitRepo) {
  editingId.value = repo.id
  const full = await gitRepoApi.getGitRepo(repo.id)
  form.value = {
    name: full.name,
    remote_url: full.remote_url,
    auth_type: full.auth_type,
    credentials: '',
    default_branch: full.default_branch,
    local_path: full.local_path,
    known_hosts: full.known_hosts || '',
    is_enabled: full.is_enabled,
  }
  drawerVisible.value = true
}

async function handleSubmit() {
  let ok: boolean
  if (editingId.value !== null) {
    const data: GitRepoUpdate = {
      name: form.value.name,
      remote_url: form.value.remote_url,
      auth_type: form.value.auth_type,
      default_branch: form.value.default_branch,
      local_path: form.value.local_path,
      known_hosts: form.value.known_hosts,
      is_enabled: form.value.is_enabled,
    }
    if (form.value.credentials) data.credentials = form.value.credentials
    ok = await update(editingId.value, data)
  } else {
    const data: GitRepoCreate = {
      name: form.value.name,
      remote_url: form.value.remote_url,
      auth_type: form.value.auth_type,
      default_branch: form.value.default_branch,
      local_path: form.value.local_path,
      known_hosts: form.value.known_hosts,
    }
    if (form.value.credentials) data.credentials = form.value.credentials
    ok = await create(data)
  }
  if (ok) drawerVisible.value = false
}

function handleDelete(repo: GitRepo) {
  confirmDelete(`Delete git repository "${repo.name}"?`, () => remove(repo.id))
}

async function handleTest(repo: GitRepo) {
  testingId.value = repo.id
  try {
    const result = await gitRepoApi.testGitRepoConnection(repo.id)
    if (result.success) {
      notifications.success('Connection successful', result.message)
    } else {
      notifications.error('Connection failed', result.message)
    }
  } catch {
    notifications.error('Connection test failed')
  } finally {
    testingId.value = null
  }
}

async function handleSync(repo: GitRepo) {
  syncingId.value = repo.id
  try {
    await gitRepoApi.syncGitRepo(repo.id)
    notifications.success('Sync completed')
    await fetchRepos()
  } catch {
    notifications.error('Sync failed')
  } finally {
    syncingId.value = null
  }
}

function syncStatusSeverity(status: string | null): string {
  if (!status) return 'secondary'
  if (status === 'ok' || status === 'success') return 'success'
  if (status === 'error' || status === 'failed') return 'danger'
  return 'warn'
}

onMounted(fetchRepos)
</script>

<template>
  <div>
    <PageHeader title="Git Repositories" subtitle="GitOps repository configuration">
      <Button v-if="isAdmin" label="Add Repository" icon="pi pi-plus" @click="openCreate" />
    </PageHeader>

    <div v-if="loading" class="skeleton-table">
      <Skeleton v-for="i in 5" :key="i" height="2.5rem" class="mb-2" />
    </div>

    <EmptyState
      v-else-if="repos.length === 0"
      icon="pi pi-github"
      message="No git repositories configured. Add one to enable GitOps."
    >
      <Button v-if="isAdmin" label="Add Repository" icon="pi pi-plus" @click="openCreate" />
    </EmptyState>

    <DataTable
      v-else
      :value="repos"
      size="small"
      paginator
      :rows="25"
      :rowsPerPageOptions="[25, 50, 100]"
      sortField="name"
      :sortOrder="1"
      stripedRows
    >
      <Column field="name" header="Name" sortable>
        <template #body="{ data }">
          <span class="font-semibold">{{ data.name }}</span>
        </template>
      </Column>
      <Column field="remote_url" header="Remote URL" sortable>
        <template #body="{ data }">
          <span class="font-mono text-sm">{{ data.remote_url || '(local only)' }}</span>
        </template>
      </Column>
      <Column field="auth_type" header="Auth" sortable style="width: 6rem">
        <template #body="{ data }">
          <Tag :value="data.auth_type" severity="secondary" />
        </template>
      </Column>
      <Column field="default_branch" header="Branch" sortable style="width: 7rem">
        <template #body="{ data }">
          <span class="font-mono text-sm">{{ data.default_branch }}</span>
        </template>
      </Column>
      <Column field="is_enabled" header="Status" sortable style="width: 6rem">
        <template #body="{ data }">
          <Tag :value="data.is_enabled ? 'Enabled' : 'Disabled'" :severity="data.is_enabled ? 'success' : 'secondary'" />
        </template>
      </Column>
      <Column field="last_sync_status" header="Last Sync" style="width: 7rem">
        <template #body="{ data }">
          <Tag v-if="data.last_sync_status" :value="data.last_sync_status" :severity="syncStatusSeverity(data.last_sync_status)" />
          <span v-else class="text-surface-400">Never</span>
        </template>
      </Column>
      <Column v-if="isAdmin" header="Actions" style="width: 10rem; text-align: right">
        <template #body="{ data }">
          <div class="action-buttons" @click.stop>
            <Button
              icon="pi pi-play"
              text
              rounded
              size="small"
              aria-label="Test"
              v-tooltip.top="'Test Connection'"
              :loading="testingId === data.id"
              @click="handleTest(data)"
            />
            <Button
              icon="pi pi-sync"
              text
              rounded
              size="small"
              aria-label="Sync"
              v-tooltip.top="'Sync'"
              :loading="syncingId === data.id"
              @click="handleSync(data)"
            />
            <Button
              icon="pi pi-pencil"
              text
              rounded
              size="small"
              aria-label="Edit"
              v-tooltip.top="'Edit'"
              @click="openEdit(data)"
            />
            <Button
              icon="pi pi-trash"
              text
              rounded
              size="small"
              severity="danger"
              aria-label="Delete"
              v-tooltip.top="'Delete'"
              @click="handleDelete(data)"
            />
          </div>
        </template>
      </Column>
    </DataTable>

    <Drawer
      v-model:visible="drawerVisible"
      :header="editingId ? 'Edit Repository' : 'Add Repository'"
      position="right"
      class="w-25rem"
    >
      <form @submit.prevent="handleSubmit" class="drawer-form">
        <div class="field">
          <label for="repo-name">Name</label>
          <InputText id="repo-name" v-model="form.name" class="w-full" placeholder="my-dns-repo" />
        </div>
        <div class="field">
          <label for="repo-url">Remote URL</label>
          <InputText
            id="repo-url"
            v-model="form.remote_url"
            class="w-full"
            placeholder="git@github.com:org/repo.git"
          />
          <small class="text-surface-400">Leave blank for local-only repos</small>
        </div>
        <div class="field">
          <label for="repo-auth">Authentication</label>
          <Select
            id="repo-auth"
            v-model="form.auth_type"
            :options="authTypeOptions"
            optionLabel="label"
            optionValue="value"
            class="w-full"
          />
        </div>
        <div v-if="showCredentials" class="field">
          <label for="repo-credentials">{{ credentialsLabel }}</label>
          <Textarea
            v-if="form.auth_type === 'ssh'"
            id="repo-credentials"
            v-model="form.credentials"
            class="w-full font-mono"
            :placeholder="credentialsPlaceholder"
            rows="6"
            autoResize
          />
          <InputText
            v-else
            id="repo-credentials"
            v-model="form.credentials"
            class="w-full"
            :placeholder="credentialsPlaceholder"
            type="password"
          />
          <small v-if="editingId" class="text-surface-400">Leave blank to keep current credentials</small>
        </div>
        <div v-if="form.auth_type === 'ssh'" class="field">
          <label for="repo-known-hosts">Known Hosts</label>
          <Textarea
            id="repo-known-hosts"
            v-model="form.known_hosts"
            class="w-full font-mono"
            placeholder="github.com ssh-ed25519 AAAA..."
            rows="3"
            autoResize
          />
        </div>
        <div class="field">
          <label for="repo-branch">Default Branch</label>
          <InputText id="repo-branch" v-model="form.default_branch" class="w-full" placeholder="main" />
        </div>
        <div class="field">
          <label for="repo-path">Local Path (optional)</label>
          <InputText
            id="repo-path"
            v-model="form.local_path"
            class="w-full font-mono"
            placeholder="/var/meridian-dns/repos/my-repo"
          />
          <small class="text-surface-400">Auto-generated if blank</small>
        </div>
        <div v-if="editingId" class="toggle-row">
          <ToggleSwitch id="repo-enabled" v-model="form.is_enabled" />
          <label for="repo-enabled" class="toggle-label">Enabled</label>
        </div>
        <Button type="submit" :label="editingId ? 'Save' : 'Create'" class="w-full" />
      </form>
    </Drawer>
  </div>
</template>

<style scoped>
.skeleton-table {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.mb-2 {
  margin-bottom: 0.5rem;
}

.action-buttons {
  display: flex;
  justify-content: flex-end;
  gap: 0.25rem;
}

.drawer-form {
  display: flex;
  flex-direction: column;
  gap: 1rem;
}

.field {
  display: flex;
  flex-direction: column;
  gap: 0.375rem;
}

.field label {
  font-size: 0.875rem;
  font-weight: 500;
}

.w-full {
  width: 100%;
}

.w-25rem {
  width: 25rem;
}

.font-mono {
  font-family: var(--font-mono, ui-monospace, monospace);
}

.font-semibold {
  font-weight: 600;
}

.text-sm {
  font-size: 0.875rem;
}

.text-surface-400 {
  color: var(--p-surface-400);
}

.toggle-row {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.toggle-label {
  font-size: 0.875rem;
  cursor: pointer;
}
</style>
