<script setup lang="ts">
import { onMounted, ref, computed } from 'vue'
import { useRoute } from 'vue-router'
import MultiSelect from 'primevue/multiselect'
import Button from 'primevue/button'
import Panel from 'primevue/panel'
import DataTable from 'primevue/datatable'
import Column from 'primevue/column'
import Tag from 'primevue/tag'
import Skeleton from 'primevue/skeleton'
import Divider from 'primevue/divider'
import PageHeader from '../components/shared/PageHeader.vue'
import { useConfirmAction } from '../composables/useConfirm'
import { useRole } from '../composables/useRole'
import { useNotificationStore } from '../stores/notification'
import { ApiRequestError } from '../api/client'
import * as zoneApi from '../api/zones'
import * as deployApi from '../api/deployments'
import type { Zone, PreviewResult, DeploymentSnapshot } from '../types'

const route = useRoute()
const { isOperator } = useRole()
const { confirmAction } = useConfirmAction()
const notify = useNotificationStore()

const allZones = ref<Zone[]>([])
const selectedZoneIds = ref<number[]>([])
const previews = ref<PreviewResult[]>([])
const previewing = ref(false)
const pushingZones = ref<Set<number>>(new Set())
const pushedZones = ref<Set<number>>(new Set())
const failedZones = ref<Set<number>>(new Set())

// Deployment history
const deployments = ref<DeploymentSnapshot[]>([])
const historyLoading = ref(false)
const expandedRows = ref<Record<string, boolean>>({})

const totalChanges = computed(() => {
  let adds = 0, mods = 0, dels = 0
  previews.value.forEach((p) => {
    p.diffs.forEach((d) => {
      if (d.action === 'add') adds++
      else if (d.action === 'update') mods++
      else if (d.action === 'delete') dels++
    })
  })
  return { adds, mods, dels }
})

const zonesWithChanges = computed(() =>
  previews.value.filter((p) => p.diffs.length > 0),
)

async function handlePreview() {
  if (selectedZoneIds.value.length === 0) return
  previewing.value = true
  previews.value = []
  pushedZones.value.clear()
  failedZones.value.clear()
  try {
    const results = await Promise.all(
      selectedZoneIds.value.map((id) => deployApi.previewZone(id)),
    )
    previews.value = results
  } catch (err) {
    const msg = err instanceof ApiRequestError ? err.body.message : 'Preview failed'
    notify.error('Preview failed', msg)
  } finally {
    previewing.value = false
  }
}

async function pushZone(zoneId: number) {
  pushingZones.value.add(zoneId)
  try {
    await deployApi.pushZone(zoneId)
    pushedZones.value.add(zoneId)
    notify.success('Deployed', `Zone ${previews.value.find((p) => p.zone_id === zoneId)?.zone_name}`)
  } catch (err) {
    failedZones.value.add(zoneId)
    const msg = err instanceof ApiRequestError ? err.body.message : 'Push failed'
    notify.error('Deploy failed', msg)
  } finally {
    pushingZones.value.delete(zoneId)
  }
}

function handlePushAll() {
  const zones = zonesWithChanges.value
  const { adds, mods, dels } = totalChanges.value
  confirmAction(
    `Deploy changes to ${zones.length} zone(s)? ${adds} adds, ${mods} modifies, ${dels} deletes.`,
    'Confirm Deployment',
    async () => {
      for (const p of zones) {
        if (!pushedZones.value.has(p.zone_id) && !failedZones.value.has(p.zone_id)) {
          await pushZone(p.zone_id)
        }
      }
      await loadHistory()
    },
  )
}

function handlePushSingle(zoneId: number) {
  const preview = previews.value.find((p) => p.zone_id === zoneId)
  confirmAction(
    `Deploy changes to zone "${preview?.zone_name}"?`,
    'Confirm Deployment',
    async () => {
      await pushZone(zoneId)
      await loadHistory()
    },
  )
}

async function loadHistory() {
  if (selectedZoneIds.value.length === 0) return
  historyLoading.value = true
  try {
    const results = await Promise.all(
      selectedZoneIds.value.map((id) => deployApi.listDeployments(id, 20)),
    )
    deployments.value = results
      .flat()
      .sort((a, b) => b.deployed_at - a.deployed_at)
      .slice(0, 50)
  } catch {
    notify.error('Failed to load deployment history')
  } finally {
    historyLoading.value = false
  }
}

async function handleRollback(dep: DeploymentSnapshot) {
  confirmAction(
    `Rollback zone to deployment #${dep.seq}? This restores records from snapshot. Use preview + push to deploy.`,
    'Confirm Rollback',
    async () => {
      try {
        await deployApi.rollback(dep.zone_id, dep.id)
        notify.success('Rollback applied', `Deployment #${dep.seq}`)
      } catch (err) {
        const msg = err instanceof ApiRequestError ? err.body.message : 'Rollback failed'
        notify.error('Rollback failed', msg)
      }
    },
  )
}

function zoneStatus(zoneId: number): string {
  if (pushedZones.value.has(zoneId)) return 'success'
  if (failedZones.value.has(zoneId)) return 'failed'
  if (pushingZones.value.has(zoneId)) return 'deploying'
  return 'pending'
}

function statusSeverity(status: string): string {
  if (status === 'success') return 'success'
  if (status === 'failed') return 'danger'
  if (status === 'deploying') return 'warn'
  return 'secondary'
}

function diffSummary(preview: PreviewResult): string {
  const counts: Record<string, number> = {}
  preview.diffs.forEach((d) => {
    counts[d.action] = (counts[d.action] || 0) + 1
  })
  return Object.entries(counts)
    .map(([k, v]) => `${v} ${k}${v > 1 ? 's' : ''}`)
    .join(', ')
}

function actionColor(action: string): string {
  if (action === 'add') return 'var(--p-green-400)'
  if (action === 'update' || action === 'drift') return 'var(--p-amber-400)'
  if (action === 'delete') return 'var(--p-red-400)'
  return 'var(--p-surface-400)'
}

function zoneName(zoneId: number): string {
  return allZones.value.find((z) => z.id === zoneId)?.name || `#${zoneId}`
}

function formatTimestamp(epoch: number): string {
  return new Date(epoch * 1000).toLocaleString()
}

onMounted(async () => {
  const zones = await zoneApi.listZones()
  allZones.value = zones

  const queryZones = route.query.zones
  if (typeof queryZones === 'string') {
    selectedZoneIds.value = queryZones.split(',').map(Number).filter(Boolean)
  }
})
</script>

<template>
  <div>
    <PageHeader title="Deployments" subtitle="Preview and push DNS changes" />

    <div class="zone-selector">
      <MultiSelect
        v-model="selectedZoneIds"
        :options="allZones"
        optionLabel="name"
        optionValue="id"
        placeholder="Select zones"
        display="chip"
        filter
        class="zone-multi-select"
      />
      <Button
        label="Preview"
        icon="pi pi-search"
        :loading="previewing"
        :disabled="selectedZoneIds.length === 0"
        @click="handlePreview"
      />
      <Button
        v-if="isOperator && zonesWithChanges.length > 0"
        label="Push All"
        icon="pi pi-play"
        severity="success"
        :disabled="previewing || pushingZones.size > 0"
        @click="handlePushAll"
      />
    </div>

    <div v-if="previewing" class="skeleton-table">
      <Skeleton v-for="i in 3" :key="i" height="4rem" class="mb-2" />
    </div>

    <div v-if="previews.length > 0" class="preview-panels">
      <Panel
        v-for="preview in previews"
        :key="preview.zone_id"
        :collapsed="preview.diffs.length === 0"
        toggleable
      >
        <template #header>
          <div class="panel-header">
            <span class="font-mono panel-zone-name">{{ preview.zone_name }}</span>
            <Tag
              v-if="preview.diffs.length === 0"
              value="In sync"
              severity="success"
              icon="pi pi-check-circle"
            />
            <Tag
              v-else
              :value="diffSummary(preview)"
              :severity="preview.has_drift ? 'warn' : 'info'"
            />
            <Tag
              v-if="zoneStatus(preview.zone_id) !== 'pending'"
              :value="zoneStatus(preview.zone_id)"
              :severity="statusSeverity(zoneStatus(preview.zone_id))"
              class="ml-2"
            />
          </div>
        </template>
        <template #icons>
          <Button
            v-if="isOperator && preview.diffs.length > 0 && !pushedZones.has(preview.zone_id)"
            label="Push"
            icon="pi pi-play"
            size="small"
            severity="success"
            :loading="pushingZones.has(preview.zone_id)"
            @click="handlePushSingle(preview.zone_id)"
          />
        </template>

        <div v-if="preview.diffs.length > 0" class="diff-list">
          <div
            v-for="(diff, idx) in preview.diffs"
            :key="idx"
            class="diff-row"
            :style="{ borderLeftColor: actionColor(diff.action) }"
          >
            <div class="diff-header">
              <Tag :value="diff.action" :severity="diff.action === 'add' ? 'success' : diff.action === 'delete' ? 'danger' : 'warn'" />
              <span class="font-mono diff-name">{{ diff.name }}</span>
              <Tag :value="diff.type" severity="secondary" />
            </div>
            <div class="diff-values">
              <div v-if="diff.source_value" class="diff-value">
                <span class="diff-label">Desired:</span>
                <span class="font-mono">{{ diff.source_value }}</span>
              </div>
              <div v-if="diff.provider_value" class="diff-value">
                <span class="diff-label">Provider:</span>
                <span class="font-mono" :class="{ 'text-muted': diff.action === 'delete' }">
                  {{ diff.provider_value }}
                </span>
              </div>
            </div>
          </div>
        </div>
        <div v-else class="in-sync">
          <i class="pi pi-check-circle" /> All records are in sync.
        </div>
      </Panel>
    </div>

    <Divider v-if="selectedZoneIds.length > 0" />

    <div v-if="selectedZoneIds.length > 0" class="history-section">
      <h3 class="section-title">Deployment History</h3>
      <Button
        label="Load History"
        icon="pi pi-refresh"
        text
        size="small"
        :loading="historyLoading"
        @click="loadHistory"
        class="mb-1"
      />

      <DataTable
        v-if="deployments.length > 0"
        :value="deployments"
        size="small"
        paginator
        :rows="25"
        stripedRows
        v-model:expandedRows="expandedRows"
        dataKey="id"
      >
        <Column expander style="width: 3rem" />
        <Column field="seq" header="#" sortable style="width: 4rem" />
        <Column header="Timestamp" sortable field="deployed_at">
          <template #body="{ data }">
            {{ formatTimestamp(data.deployed_at) }}
          </template>
        </Column>
        <Column header="Zone">
          <template #body="{ data }">
            <span class="font-mono">{{ zoneName(data.zone_id) }}</span>
          </template>
        </Column>
        <Column v-if="isOperator" header="Actions" style="width: 6rem">
          <template #body="{ data }">
            <Button
              icon="pi pi-undo"
              text
              rounded
              size="small"
              aria-label="Rollback"
              v-tooltip.top="'Rollback'"
              @click="handleRollback(data)"
            />
          </template>
        </Column>
        <template #expansion="{ data }">
          <div class="expansion-content">
            <pre class="font-mono snapshot-json">{{ JSON.stringify(data.snapshot, null, 2) }}</pre>
          </div>
        </template>
      </DataTable>
    </div>
  </div>
</template>

<style scoped>
.zone-selector {
  display: flex;
  gap: 0.75rem;
  align-items: flex-start;
  margin-bottom: 1.5rem;
}

.zone-multi-select {
  min-width: 20rem;
  flex: 1;
  max-width: 40rem;
}

.skeleton-table {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.mb-2 {
  margin-bottom: 0.5rem;
}

.mb-1 {
  margin-bottom: 0.25rem;
}

.ml-2 {
  margin-left: 0.5rem;
}

.preview-panels {
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
}

.panel-header {
  display: flex;
  align-items: center;
  gap: 0.75rem;
}

.panel-zone-name {
  font-weight: 600;
}

.diff-list {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.diff-row {
  border-left: 4px solid;
  padding: 0.5rem 0.75rem;
  background: var(--p-surface-800);
  border-radius: 0 0.25rem 0.25rem 0;
}

:root:not(.app-dark) .diff-row {
  background: var(--p-surface-100);
}

.diff-header {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  margin-bottom: 0.25rem;
}

.diff-name {
  font-weight: 500;
}

.diff-values {
  display: flex;
  flex-direction: column;
  gap: 0.125rem;
  font-size: 0.85rem;
}

.diff-value {
  display: flex;
  gap: 0.5rem;
}

.diff-label {
  color: var(--p-surface-400);
  min-width: 5rem;
}

.text-muted {
  color: var(--p-surface-400);
  text-decoration: line-through;
}

.in-sync {
  color: var(--p-green-400);
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.history-section {
  margin-top: 1rem;
}

.section-title {
  font-size: 1.1rem;
  font-weight: 600;
  margin: 0 0 0.5rem;
  color: var(--p-surface-200);
}

:root:not(.app-dark) .section-title {
  color: var(--p-surface-700);
}

.expansion-content {
  padding: 0.5rem;
}

.snapshot-json {
  font-size: 0.8rem;
  max-height: 20rem;
  overflow: auto;
  background: var(--p-surface-900);
  padding: 0.75rem;
  border-radius: 0.25rem;
  margin: 0;
}

:root:not(.app-dark) .snapshot-json {
  background: var(--p-surface-50);
}
</style>
