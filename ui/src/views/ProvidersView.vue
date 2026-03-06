<script setup lang="ts">
import { onMounted, ref } from 'vue'
import DataTable from 'primevue/datatable'
import Column from 'primevue/column'
import Button from 'primevue/button'
import Drawer from 'primevue/drawer'
import InputText from 'primevue/inputtext'
import Select from 'primevue/select'
import Password from 'primevue/password'
import Skeleton from 'primevue/skeleton'
import Tag from 'primevue/tag'
import PageHeader from '../components/shared/PageHeader.vue'
import EmptyState from '../components/shared/EmptyState.vue'
import { useCrud } from '../composables/useCrud'
import { useConfirmAction } from '../composables/useConfirm'
import { useRole } from '../composables/useRole'
import * as api from '../api/providers'
import type { Provider, ProviderCreate, ProviderUpdate } from '../types'

const { isAdmin } = useRole()
const { confirmDelete } = useConfirmAction()

const { items: providers, loading, fetch: fetchProviders, create, update, remove } = useCrud<
  Provider,
  ProviderCreate,
  ProviderUpdate
>(
  {
    list: api.listProviders,
    create: api.createProvider,
    update: (id: number, data: ProviderUpdate) => api.updateProvider(id, data),
    remove: api.deleteProvider,
  },
  'Provider',
)

const drawerVisible = ref(false)
const editingId = ref<number | null>(null)
const form = ref({
  name: '',
  type: 'powerdns',
  api_endpoint: '',
  token: '',
})

const providerTypes = [
  { label: 'PowerDNS', value: 'powerdns' },
  { label: 'Cloudflare', value: 'cloudflare' },
  { label: 'DigitalOcean', value: 'digitalocean' },
]

function openCreate() {
  editingId.value = null
  form.value = { name: '', type: 'powerdns', api_endpoint: '', token: '' }
  drawerVisible.value = true
}

async function openEdit(provider: Provider) {
  const full = await api.getProvider(provider.id)
  editingId.value = provider.id
  form.value = {
    name: full.name,
    type: full.type,
    api_endpoint: full.api_endpoint,
    token: '',
  }
  drawerVisible.value = true
}

async function handleSubmit() {
  let ok: boolean
  if (editingId.value !== null) {
    const data: ProviderUpdate = {
      name: form.value.name,
      api_endpoint: form.value.api_endpoint,
    }
    if (form.value.token) {
      data.token = form.value.token
    }
    ok = await update(editingId.value, data)
  } else {
    ok = await create(form.value as ProviderCreate)
  }
  if (ok) {
    drawerVisible.value = false
  }
}

function handleDelete(provider: Provider) {
  confirmDelete(`Delete provider "${provider.name}"?`, () => remove(provider.id))
}

onMounted(fetchProviders)
</script>

<template>
  <div>
    <PageHeader title="Providers" subtitle="DNS provider connections">
      <Button
        v-if="isAdmin"
        label="Add Provider"
        icon="pi pi-plus"
        @click="openCreate"
      />
    </PageHeader>

    <div v-if="loading" class="skeleton-table">
      <Skeleton v-for="i in 5" :key="i" height="2.5rem" class="mb-2" />
    </div>

    <EmptyState
      v-else-if="providers.length === 0"
      icon="pi pi-server"
      message="No providers yet. Add your first provider."
    >
      <Button
        v-if="isAdmin"
        label="Add Provider"
        icon="pi pi-plus"
        @click="openCreate"
      />
    </EmptyState>

    <DataTable
      v-else
      :value="providers"
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
          <span class="font-mono">{{ data.name }}</span>
        </template>
      </Column>
      <Column field="type" header="Type" sortable>
        <template #body="{ data }">
          <Tag :value="data.type" severity="secondary" />
        </template>
      </Column>
      <Column field="api_endpoint" header="API Endpoint" />
      <Column v-if="isAdmin" header="Actions" style="width: 6rem; text-align: right">
        <template #body="{ data }">
          <div class="action-buttons">
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
      :header="editingId ? 'Edit Provider' : 'Add Provider'"
      position="right"
      class="w-25rem"
    >
      <form @submit.prevent="handleSubmit" class="drawer-form">
        <div class="field">
          <label for="prov-name">Name</label>
          <InputText id="prov-name" v-model="form.name" class="w-full" />
        </div>
        <div class="field" v-if="!editingId">
          <label for="prov-type">Type</label>
          <Select
            id="prov-type"
            v-model="form.type"
            :options="providerTypes"
            optionLabel="label"
            optionValue="value"
            class="w-full"
          />
        </div>
        <div class="field">
          <label for="prov-endpoint">API Endpoint</label>
          <InputText id="prov-endpoint" v-model="form.api_endpoint" class="w-full" />
        </div>
        <div class="field">
          <label for="prov-token">
            {{ editingId ? 'Token (leave blank to keep current)' : 'Token' }}
          </label>
          <Password
            id="prov-token"
            v-model="form.token"
            :feedback="false"
            toggleMask
            class="w-full"
            inputClass="w-full"
          />
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
</style>
