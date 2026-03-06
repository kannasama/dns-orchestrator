<script setup lang="ts">
import { onMounted, ref, watch } from 'vue'
import DataTable from 'primevue/datatable'
import Column from 'primevue/column'
import Button from 'primevue/button'
import Drawer from 'primevue/drawer'
import InputText from 'primevue/inputtext'
import Select from 'primevue/select'
import Skeleton from 'primevue/skeleton'
import Tag from 'primevue/tag'
import PageHeader from '../components/shared/PageHeader.vue'
import EmptyState from '../components/shared/EmptyState.vue'
import { useConfirmAction } from '../composables/useConfirm'
import { useRole } from '../composables/useRole'
import { useNotificationStore } from '../stores/notification'
import { ApiRequestError } from '../api/client'
import * as varApi from '../api/variables'
import * as zoneApi from '../api/zones'
import type { Variable, VariableCreate, Zone } from '../types'

const { isOperator } = useRole()
const { confirmDelete } = useConfirmAction()
const notify = useNotificationStore()

const variables = ref<Variable[]>([])
const allZones = ref<Zone[]>([])
const loading = ref(true)

const filterScope = ref<string | null>(null)
const filterZoneId = ref<number | null>(null)

const scopeOptions = [
  { label: 'All', value: null },
  { label: 'Global', value: 'global' },
  { label: 'Zone', value: 'zone' },
]

const drawerVisible = ref(false)
const editingId = ref<number | null>(null)
const form = ref<VariableCreate>({
  name: '',
  value: '',
  type: 'string',
  scope: 'global',
  zone_id: null,
})

async function fetchVariables() {
  loading.value = true
  try {
    variables.value = await varApi.listVariables(
      filterScope.value || undefined,
      filterZoneId.value || undefined,
    )
  } catch {
    notify.error('Failed to load variables')
  } finally {
    loading.value = false
  }
}

watch([filterScope, filterZoneId], fetchVariables)

function openCreate() {
  editingId.value = null
  form.value = { name: '', value: '', type: 'string', scope: 'global', zone_id: null }
  drawerVisible.value = true
}

function openEdit(variable: Variable) {
  editingId.value = variable.id
  form.value = {
    name: variable.name,
    value: variable.value,
    type: variable.type,
    scope: variable.scope,
    zone_id: variable.zone_id,
  }
  drawerVisible.value = true
}

async function handleSubmit() {
  try {
    if (editingId.value !== null) {
      await varApi.updateVariable(editingId.value, form.value.value)
      notify.success('Variable updated')
    } else {
      await varApi.createVariable(form.value)
      notify.success('Variable created')
    }
    drawerVisible.value = false
    await fetchVariables()
  } catch (err) {
    const msg = err instanceof ApiRequestError ? err.body.message : 'Failed to save'
    notify.error('Error', msg)
  }
}

function handleDelete(variable: Variable) {
  confirmDelete(`Delete variable "${variable.name}"?`, async () => {
    try {
      await varApi.deleteVariable(variable.id)
      notify.success('Variable deleted')
      await fetchVariables()
    } catch (err) {
      const msg = err instanceof ApiRequestError ? err.body.message : 'Failed to delete'
      notify.error('Error', msg)
    }
  })
}

function zoneName(zoneId: number | null): string {
  if (!zoneId) return ''
  return allZones.value.find((z) => z.id === zoneId)?.name || `#${zoneId}`
}

onMounted(async () => {
  await Promise.all([fetchVariables(), zoneApi.listZones().then((z) => (allZones.value = z))])
})
</script>

<template>
  <div>
    <PageHeader title="Variables" subtitle="Template variable management">
      <Button v-if="isOperator" label="Add Variable" icon="pi pi-plus" @click="openCreate" />
    </PageHeader>

    <div class="filters">
      <Select
        v-model="filterScope"
        :options="scopeOptions"
        optionLabel="label"
        optionValue="value"
        placeholder="Scope"
        class="filter-select"
      />
      <Select
        v-model="filterZoneId"
        :options="[{ name: 'All zones', id: null }, ...allZones]"
        optionLabel="name"
        optionValue="id"
        placeholder="Zone"
        class="filter-select"
      />
    </div>

    <div v-if="loading" class="skeleton-table">
      <Skeleton v-for="i in 5" :key="i" height="2.5rem" class="mb-2" />
    </div>

    <EmptyState
      v-else-if="variables.length === 0"
      icon="pi pi-code"
      message="No variables found."
    >
      <Button v-if="isOperator" label="Add Variable" icon="pi pi-plus" @click="openCreate" />
    </EmptyState>

    <DataTable
      v-else
      :value="variables"
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
      <Column field="value" header="Value">
        <template #body="{ data }">
          <span class="font-mono truncate">{{ data.value }}</span>
        </template>
      </Column>
      <Column field="scope" header="Scope" sortable style="width: 7rem">
        <template #body="{ data }">
          <Tag
            :value="data.scope"
            :severity="data.scope === 'global' ? 'info' : 'warn'"
          />
        </template>
      </Column>
      <Column header="Zone" style="width: 10rem">
        <template #body="{ data }">
          <span v-if="data.zone_id" class="font-mono">{{ zoneName(data.zone_id) }}</span>
          <span v-else class="text-muted">&mdash;</span>
        </template>
      </Column>
      <Column v-if="isOperator" header="Actions" style="width: 6rem; text-align: right">
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
      :header="editingId ? 'Edit Variable' : 'Add Variable'"
      position="right"
      class="w-25rem"
    >
      <form @submit.prevent="handleSubmit" class="drawer-form">
        <div class="field">
          <label for="var-name">Name</label>
          <InputText
            id="var-name"
            v-model="form.name"
            class="w-full font-mono"
            :disabled="!!editingId"
            pattern="^[a-zA-Z_][a-zA-Z0-9_]*$"
          />
        </div>
        <div class="field">
          <label for="var-value">Value</label>
          <InputText id="var-value" v-model="form.value" class="w-full font-mono" />
        </div>
        <template v-if="!editingId">
          <div class="field">
            <label for="var-scope">Scope</label>
            <Select
              id="var-scope"
              v-model="form.scope"
              :options="[{ label: 'Global', value: 'global' }, { label: 'Zone', value: 'zone' }]"
              optionLabel="label"
              optionValue="value"
              class="w-full"
            />
          </div>
          <div class="field" v-if="form.scope === 'zone'">
            <label for="var-zone">Zone</label>
            <Select
              id="var-zone"
              v-model="form.zone_id"
              :options="allZones"
              optionLabel="name"
              optionValue="id"
              placeholder="Select a zone"
              class="w-full"
            />
          </div>
        </template>
        <Button type="submit" :label="editingId ? 'Save' : 'Create'" class="w-full" />
      </form>
    </Drawer>
  </div>
</template>

<style scoped>
.filters {
  display: flex;
  gap: 0.75rem;
  margin-bottom: 1rem;
}

.filter-select {
  width: 12rem;
}

.skeleton-table {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.mb-2 {
  margin-bottom: 0.5rem;
}

.truncate {
  max-width: 20rem;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  display: inline-block;
}

.text-muted {
  color: var(--p-surface-400);
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
