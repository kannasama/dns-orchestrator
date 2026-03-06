<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import DataTable from 'primevue/datatable'
import Column from 'primevue/column'
import Button from 'primevue/button'
import Drawer from 'primevue/drawer'
import InputText from 'primevue/inputtext'
import InputNumber from 'primevue/inputnumber'
import Select from 'primevue/select'
import Skeleton from 'primevue/skeleton'
import ToggleSwitch from 'primevue/toggleswitch'
import PageHeader from '../components/shared/PageHeader.vue'
import EmptyState from '../components/shared/EmptyState.vue'
import { useCrud } from '../composables/useCrud'
import { useConfirmAction } from '../composables/useConfirm'
import { useRole } from '../composables/useRole'
import * as zoneApi from '../api/zones'
import * as viewApi from '../api/views'
import type { Zone, ZoneCreate, View } from '../types'

const router = useRouter()
const { isAdmin } = useRole()
const { confirmDelete } = useConfirmAction()

const { items: zones, loading, fetch: fetchZones, create, update, remove } = useCrud<
  Zone,
  ZoneCreate,
  { name: string; deployment_retention?: number | null; manage_soa?: boolean; manage_ns?: boolean }
>(
  {
    list: () => zoneApi.listZones(),
    create: zoneApi.createZone,
    update: (id: number, data: { name: string; deployment_retention?: number | null; manage_soa?: boolean; manage_ns?: boolean }) =>
      zoneApi.updateZone(id, data),
    remove: zoneApi.deleteZone,
  },
  'Zone',
)

const allViews = ref<View[]>([])
const drawerVisible = ref(false)
const editingId = ref<number | null>(null)
const form = ref({
  name: '',
  view_id: null as number | null,
  deployment_retention: null as number | null,
  manage_soa: false,
  manage_ns: false,
})

function openCreate() {
  editingId.value = null
  form.value = { name: '', view_id: null, deployment_retention: null, manage_soa: false, manage_ns: false }
  drawerVisible.value = true
}

function openEdit(zone: Zone) {
  editingId.value = zone.id
  form.value = {
    name: zone.name,
    view_id: zone.view_id,
    deployment_retention: zone.deployment_retention,
    manage_soa: zone.manage_soa,
    manage_ns: zone.manage_ns,
  }
  drawerVisible.value = true
}

async function handleSubmit() {
  let ok: boolean
  if (editingId.value !== null) {
    ok = await update(editingId.value, {
      name: form.value.name,
      deployment_retention: form.value.deployment_retention,
      manage_soa: form.value.manage_soa,
      manage_ns: form.value.manage_ns,
    })
  } else {
    ok = await create({
      name: form.value.name,
      view_id: form.value.view_id!,
      deployment_retention: form.value.deployment_retention,
      manage_soa: form.value.manage_soa,
      manage_ns: form.value.manage_ns,
    })
  }
  if (ok) drawerVisible.value = false
}

function handleDelete(zone: Zone) {
  confirmDelete(`Delete zone "${zone.name}"?`, () => remove(zone.id))
}

function viewName(viewId: number): string {
  return allViews.value.find((v) => v.id === viewId)?.name || `#${viewId}`
}

function navigateToZone(zone: Zone) {
  router.push({ name: 'zone-detail', params: { id: zone.id } })
}

onMounted(async () => {
  await Promise.all([fetchZones(), viewApi.listViews().then((v) => (allViews.value = v))])
})
</script>

<template>
  <div>
    <PageHeader title="Zones" subtitle="DNS zones">
      <Button v-if="isAdmin" label="Add Zone" icon="pi pi-plus" @click="openCreate" />
    </PageHeader>

    <div v-if="loading" class="skeleton-table">
      <Skeleton v-for="i in 5" :key="i" height="2.5rem" class="mb-2" />
    </div>

    <EmptyState
      v-else-if="zones.length === 0"
      icon="pi pi-globe"
      message="No zones yet. Add your first zone."
    >
      <Button v-if="isAdmin" label="Add Zone" icon="pi pi-plus" @click="openCreate" />
    </EmptyState>

    <DataTable
      v-else
      :value="zones"
      size="small"
      paginator
      :rows="25"
      :rowsPerPageOptions="[25, 50, 100]"
      sortField="name"
      :sortOrder="1"
      stripedRows
      selectionMode="single"
      @rowSelect="(e: any) => navigateToZone(e.data)"
      class="cursor-pointer"
    >
      <Column field="name" header="Name" sortable>
        <template #body="{ data }">
          <span class="font-mono">{{ data.name }}</span>
        </template>
      </Column>
      <Column field="view_id" header="View" sortable>
        <template #body="{ data }">
          {{ viewName(data.view_id) }}
        </template>
      </Column>
      <Column v-if="isAdmin" header="Actions" style="width: 6rem; text-align: right">
        <template #body="{ data }">
          <div class="action-buttons" @click.stop>
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
      :header="editingId ? 'Edit Zone' : 'Add Zone'"
      position="right"
      class="w-25rem"
    >
      <form @submit.prevent="handleSubmit" class="drawer-form">
        <div class="field">
          <label for="zone-name">Name</label>
          <InputText id="zone-name" v-model="form.name" class="w-full" placeholder="example.com" />
        </div>
        <div class="field" v-if="!editingId">
          <label for="zone-view">View</label>
          <Select
            id="zone-view"
            v-model="form.view_id"
            :options="allViews"
            optionLabel="name"
            optionValue="id"
            placeholder="Select a view"
            class="w-full"
          />
        </div>
        <div class="field">
          <label for="zone-retention">Deployment Retention (optional)</label>
          <InputNumber
            id="zone-retention"
            v-model="form.deployment_retention"
            :min="1"
            :max="1000"
            class="w-full"
            placeholder="Default"
          />
        </div>
        <div class="field-group">
          <label class="field-group-label">Record Management</label>
          <div class="toggle-row">
            <ToggleSwitch id="zone-manage-soa" v-model="form.manage_soa" />
            <label for="zone-manage-soa" class="toggle-label" v-tooltip.right="'When enabled, SOA records are included in diff previews and deployments. Usually leave off — most providers manage SOA automatically.'">Manage SOA records</label>
          </div>
          <div class="toggle-row">
            <ToggleSwitch id="zone-manage-ns" v-model="form.manage_ns" />
            <label for="zone-manage-ns" class="toggle-label" v-tooltip.right="'When enabled, NS records are included in diff previews and deployments. Enable for self-hosted providers (e.g. PowerDNS).'">Manage NS records</label>
          </div>
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

.cursor-pointer :deep(tr) {
  cursor: pointer;
}

.field-group {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.field-group-label {
  font-size: 0.875rem;
  font-weight: 500;
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
