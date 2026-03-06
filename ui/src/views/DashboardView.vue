<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import Tag from 'primevue/tag'
import DataTable from 'primevue/datatable'
import Column from 'primevue/column'
import Skeleton from 'primevue/skeleton'
import PageHeader from '../components/shared/PageHeader.vue'
import * as providerApi from '../api/providers'
import * as zoneApi from '../api/zones'
import * as healthApi from '../api/health'
import type { Zone } from '../types'

const router = useRouter()

const zoneCount = ref(0)
const providerCount = ref(0)
const healthStatus = ref<string>('unknown')
const zones = ref<Zone[]>([])
const loading = ref(true)

const stats = ref([
  { label: 'Zones', icon: 'pi pi-globe', value: 0 },
  { label: 'Providers', icon: 'pi pi-server', value: 0 },
])

onMounted(async () => {
  try {
    const [providers, allZones, health] = await Promise.all([
      providerApi.listProviders(),
      zoneApi.listZones(),
      healthApi.getHealth().catch(() => ({ status: 'unreachable' })),
    ])
    providerCount.value = providers.length
    zoneCount.value = allZones.length
    zones.value = allZones
    healthStatus.value = health.status

    stats.value = [
      { label: 'Zones', icon: 'pi pi-globe', value: allZones.length },
      { label: 'Providers', icon: 'pi pi-server', value: providers.length },
    ]
  } finally {
    loading.value = false
  }
})

function navigateToZone(zone: Zone) {
  router.push({ name: 'zone-detail', params: { id: zone.id } })
}
</script>

<template>
  <div>
    <PageHeader title="Dashboard" subtitle="System overview" />

    <div v-if="loading" class="stats-grid">
      <Skeleton v-for="i in 3" :key="i" height="5rem" />
    </div>

    <template v-else>
      <div class="stats-grid">
        <div v-for="stat in stats" :key="stat.label" class="stat-card">
          <div class="stat-icon">
            <i :class="stat.icon" />
          </div>
          <div class="stat-content">
            <span class="stat-value">{{ stat.value }}</span>
            <span class="stat-label">{{ stat.label }}</span>
          </div>
        </div>
        <div class="stat-card">
          <div class="stat-icon">
            <i
              :class="healthStatus === 'ok' ? 'pi pi-check-circle' : 'pi pi-exclamation-triangle'"
            />
          </div>
          <div class="stat-content">
            <Tag
              :value="healthStatus"
              :severity="healthStatus === 'ok' ? 'success' : 'danger'"
            />
            <span class="stat-label">System Health</span>
          </div>
        </div>
      </div>

      <h3 class="section-title">Zones</h3>
      <DataTable
        v-if="zones.length > 0"
        :value="zones.slice(0, 10)"
        size="small"
        stripedRows
        selectionMode="single"
        @rowSelect="(e: any) => navigateToZone(e.data)"
        class="cursor-pointer"
      >
        <Column field="name" header="Name">
          <template #body="{ data }">
            <span class="font-mono">{{ data.name }}</span>
          </template>
        </Column>
      </DataTable>
    </template>
  </div>
</template>

<style scoped>
.stats-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(14rem, 1fr));
  gap: 1rem;
  margin-bottom: 1.5rem;
}

.stat-card {
  display: flex;
  align-items: center;
  gap: 1rem;
  padding: 1rem 1.25rem;
  background: var(--p-surface-900);
  border: 1px solid var(--p-surface-700);
  border-radius: 0.5rem;
}

:root:not(.app-dark) .stat-card {
  background: var(--p-surface-50);
  border-color: var(--p-surface-200);
}

.stat-icon {
  font-size: 1.5rem;
  color: var(--p-primary-400);
}

:root:not(.app-dark) .stat-icon {
  color: var(--p-primary-600);
}

.stat-content {
  display: flex;
  flex-direction: column;
}

.stat-value {
  font-size: 1.5rem;
  font-weight: 700;
  line-height: 1;
  color: var(--p-surface-0);
}

:root:not(.app-dark) .stat-value {
  color: var(--p-surface-900);
}

.stat-label {
  font-size: 0.8rem;
  color: var(--p-surface-400);
  margin-top: 0.25rem;
}

.section-title {
  font-size: 1.1rem;
  font-weight: 600;
  margin: 0 0 0.75rem;
  color: var(--p-surface-200);
}

:root:not(.app-dark) .section-title {
  color: var(--p-surface-700);
}

.cursor-pointer :deep(tr) {
  cursor: pointer;
}
</style>
