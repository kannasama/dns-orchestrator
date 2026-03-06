<script setup lang="ts">
import { onMounted, ref } from 'vue'
import DataTable from 'primevue/datatable'
import Column from 'primevue/column'
import Button from 'primevue/button'
import Select from 'primevue/select'
import DatePicker from 'primevue/datepicker'
import InputText from 'primevue/inputtext'
import Tag from 'primevue/tag'
import Skeleton from 'primevue/skeleton'
import PageHeader from '../components/shared/PageHeader.vue'
import EmptyState from '../components/shared/EmptyState.vue'
import { useConfirmAction } from '../composables/useConfirm'
import { useRole } from '../composables/useRole'
import { useNotificationStore } from '../stores/notification'
import { ApiRequestError } from '../api/client'
import * as auditApi from '../api/audit'
import type { AuditEntry } from '../types'

const { isAdmin } = useRole()
const { confirmAction } = useConfirmAction()
const notify = useNotificationStore()

const entries = ref<AuditEntry[]>([])
const loading = ref(true)
const expandedRows = ref<Record<string, boolean>>({})

const filterEntityType = ref<string | null>(null)
const filterIdentity = ref('')
const filterDateRange = ref<Date[] | null>(null)

const entityTypeOptions = [
  { label: 'All', value: null },
  { label: 'Provider', value: 'provider' },
  { label: 'View', value: 'view' },
  { label: 'Zone', value: 'zone' },
  { label: 'Record', value: 'record' },
  { label: 'Variable', value: 'variable' },
  { label: 'Deployment', value: 'deployment' },
  { label: 'User', value: 'user' },
  { label: 'Session', value: 'session' },
  { label: 'API Key', value: 'api_key' },
  { label: 'Audit', value: 'audit' },
]

async function fetchAudit() {
  loading.value = true
  try {
    const query: auditApi.AuditQuery = { limit: 200 }
    if (filterEntityType.value) query.entity_type = filterEntityType.value
    if (filterIdentity.value) query.identity = filterIdentity.value
    if (filterDateRange.value?.[0]) query.from = filterDateRange.value[0].toISOString()
    if (filterDateRange.value?.[1]) query.to = filterDateRange.value[1].toISOString()
    entries.value = await auditApi.queryAudit(query)
  } catch {
    notify.error('Failed to load audit log')
  } finally {
    loading.value = false
  }
}

async function handleExport() {
  try {
    const from = filterDateRange.value?.[0]?.toISOString()
    const to = filterDateRange.value?.[1]?.toISOString()
    const data = await auditApi.exportAudit(from, to)
    const blob = new Blob([data as unknown as string], { type: 'application/x-ndjson' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `audit-export-${new Date().toISOString().slice(0, 10)}.ndjson`
    a.click()
    URL.revokeObjectURL(url)
  } catch (err) {
    const msg = err instanceof ApiRequestError ? err.body.message : 'Export failed'
    notify.error('Export failed', msg)
  }
}

function handlePurge() {
  confirmAction(
    'Purge old audit entries? This cannot be undone.',
    'Confirm Purge',
    async () => {
      try {
        const result = await auditApi.purgeAudit()
        notify.success('Audit purged', `${result.deleted} entries removed`)
        await fetchAudit()
      } catch (err) {
        const msg = err instanceof ApiRequestError ? err.body.message : 'Purge failed'
        notify.error('Purge failed', msg)
      }
    },
  )
}

function operationSeverity(op: string): string {
  if (op === 'create' || op === 'insert') return 'success'
  if (op === 'update') return 'warn'
  if (op === 'delete' || op === 'purge') return 'danger'
  return 'info'
}

function truncate(str: string, len: number): string {
  if (!str) return ''
  return str.length > len ? str.slice(0, len) + '...' : str
}

onMounted(fetchAudit)
</script>

<template>
  <div>
    <PageHeader title="Audit Log" subtitle="System activity history">
      <Button label="Export" icon="pi pi-download" severity="secondary" @click="handleExport" class="mr-2" />
      <Button v-if="isAdmin" label="Purge" icon="pi pi-trash" severity="danger" @click="handlePurge" />
    </PageHeader>

    <div class="filters">
      <Select
        v-model="filterEntityType"
        :options="entityTypeOptions"
        optionLabel="label"
        optionValue="value"
        placeholder="Entity type"
        class="filter-field"
      />
      <InputText
        v-model="filterIdentity"
        placeholder="User"
        class="filter-field"
      />
      <DatePicker
        v-model="filterDateRange"
        selectionMode="range"
        placeholder="Date range"
        dateFormat="yy-mm-dd"
        class="filter-field"
      />
      <Button label="Search" icon="pi pi-search" :loading="loading" @click="fetchAudit" />
    </div>

    <div v-if="loading" class="skeleton-table">
      <Skeleton v-for="i in 8" :key="i" height="2.5rem" class="mb-2" />
    </div>

    <EmptyState
      v-else-if="entries.length === 0"
      icon="pi pi-history"
      message="No audit entries found."
    />

    <DataTable
      v-else
      :value="entries"
      size="small"
      paginator
      :rows="50"
      :rowsPerPageOptions="[25, 50, 100]"
      stripedRows
      v-model:expandedRows="expandedRows"
      dataKey="id"
    >
      <Column expander style="width: 3rem" />
      <Column field="timestamp" header="Timestamp" sortable style="width: 12rem">
        <template #body="{ data }">
          {{ new Date(data.timestamp).toLocaleString() }}
        </template>
      </Column>
      <Column field="identity" header="User" sortable style="width: 8rem" />
      <Column field="operation" header="Action" sortable style="width: 6rem">
        <template #body="{ data }">
          <Tag :value="data.operation" :severity="operationSeverity(data.operation)" />
        </template>
      </Column>
      <Column field="entity_type" header="Entity" sortable style="width: 7rem">
        <template #body="{ data }">
          <Tag :value="data.entity_type" severity="secondary" />
        </template>
      </Column>
      <Column header="Details">
        <template #body="{ data }">
          <span class="font-mono text-sm">
            {{ truncate(JSON.stringify(data.new_value || data.old_value || {}), 60) }}
          </span>
        </template>
      </Column>
      <template #expansion="{ data }">
        <div class="expansion-content">
          <div v-if="data.old_value" class="detail-section">
            <h4>Previous Value</h4>
            <pre class="font-mono detail-json">{{ JSON.stringify(data.old_value, null, 2) }}</pre>
          </div>
          <div v-if="data.new_value" class="detail-section">
            <h4>New Value</h4>
            <pre class="font-mono detail-json">{{ JSON.stringify(data.new_value, null, 2) }}</pre>
          </div>
          <div class="detail-meta">
            <span>Auth: {{ data.auth_method }}</span>
            <span>IP: {{ data.ip_address }}</span>
            <span v-if="data.variable_used">Variable: {{ data.variable_used }}</span>
          </div>
        </div>
      </template>
    </DataTable>
  </div>
</template>

<style scoped>
.filters {
  display: flex;
  gap: 0.75rem;
  margin-bottom: 1rem;
  flex-wrap: wrap;
}

.filter-field {
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

.mr-2 {
  margin-right: 0.5rem;
}

.text-sm {
  font-size: 0.85rem;
}

.expansion-content {
  padding: 0.75rem;
}

.detail-section {
  margin-bottom: 0.75rem;
}

.detail-section h4 {
  font-size: 0.85rem;
  font-weight: 600;
  margin: 0 0 0.25rem;
  color: var(--p-surface-300);
}

:root:not(.app-dark) .detail-section h4 {
  color: var(--p-surface-600);
}

.detail-json {
  font-size: 0.8rem;
  max-height: 15rem;
  overflow: auto;
  background: var(--p-surface-900);
  padding: 0.5rem;
  border-radius: 0.25rem;
  margin: 0;
}

:root:not(.app-dark) .detail-json {
  background: var(--p-surface-50);
}

.detail-meta {
  display: flex;
  gap: 1.5rem;
  font-size: 0.8rem;
  color: var(--p-surface-400);
}
</style>
