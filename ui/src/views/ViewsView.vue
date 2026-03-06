<script setup lang="ts">
import { onMounted, ref } from 'vue'
import DataTable from 'primevue/datatable'
import Column from 'primevue/column'
import Button from 'primevue/button'
import Drawer from 'primevue/drawer'
import InputText from 'primevue/inputtext'
import MultiSelect from 'primevue/multiselect'
import Skeleton from 'primevue/skeleton'
import Tag from 'primevue/tag'
import PageHeader from '../components/shared/PageHeader.vue'
import EmptyState from '../components/shared/EmptyState.vue'
import { useCrud } from '../composables/useCrud'
import { useConfirmAction } from '../composables/useConfirm'
import { useRole } from '../composables/useRole'
import * as viewApi from '../api/views'
import * as providerApi from '../api/providers'
import type { View, ViewCreate, Provider } from '../types'

const { isAdmin } = useRole()
const { confirmDelete } = useConfirmAction()

const { items: views, loading, fetch: fetchViews, create, update, remove } = useCrud<
  View,
  ViewCreate,
  ViewCreate
>(
  {
    list: viewApi.listViews,
    create: viewApi.createView,
    update: (id: number, data: ViewCreate) => viewApi.updateView(id, data),
    remove: viewApi.deleteView,
  },
  'View',
)

const allProviders = ref<Provider[]>([])
const drawerVisible = ref(false)
const editingId = ref<number | null>(null)
const form = ref({
  name: '',
  description: '',
  providerIds: [] as number[],
})

function openCreate() {
  editingId.value = null
  form.value = { name: '', description: '', providerIds: [] }
  drawerVisible.value = true
}

async function openEdit(view: View) {
  const full = await viewApi.getView(view.id)
  editingId.value = view.id
  form.value = {
    name: full.name,
    description: full.description || '',
    providerIds: full.provider_ids || [],
  }
  drawerVisible.value = true
}

async function syncProviders(viewId: number, desired: number[], current: number[]) {
  const toAttach = desired.filter((id) => !current.includes(id))
  const toDetach = current.filter((id) => !desired.includes(id))
  await Promise.all([
    ...toAttach.map((pid) => viewApi.attachProvider(viewId, pid)),
    ...toDetach.map((pid) => viewApi.detachProvider(viewId, pid)),
  ])
}

async function handleSubmit() {
  if (editingId.value !== null) {
    const currentView = views.value.find((v) => v.id === editingId.value)
    const ok = await update(editingId.value, {
      name: form.value.name,
      description: form.value.description || undefined,
    })
    if (ok) {
      await syncProviders(
        editingId.value,
        form.value.providerIds,
        currentView?.provider_ids || [],
      )
      await fetchViews()
      drawerVisible.value = false
    }
  } else {
    const ok = await create({
      name: form.value.name,
      description: form.value.description || undefined,
    })
    if (ok && form.value.providerIds.length > 0) {
      const created = views.value[views.value.length - 1]
      if (created) {
        await syncProviders(created.id, form.value.providerIds, [])
        await fetchViews()
      }
    }
    if (ok) drawerVisible.value = false
  }
}

function handleDelete(view: View) {
  confirmDelete(`Delete view "${view.name}"?`, () => remove(view.id))
}

function providerName(id: number): string {
  return allProviders.value.find((p) => p.id === id)?.name || `#${id}`
}

onMounted(async () => {
  await Promise.all([fetchViews(), providerApi.listProviders().then((p) => (allProviders.value = p))])
})
</script>

<template>
  <div>
    <PageHeader title="Views" subtitle="Logical groupings of providers">
      <Button v-if="isAdmin" label="Add View" icon="pi pi-plus" @click="openCreate" />
    </PageHeader>

    <div v-if="loading" class="skeleton-table">
      <Skeleton v-for="i in 5" :key="i" height="2.5rem" class="mb-2" />
    </div>

    <EmptyState
      v-else-if="views.length === 0"
      icon="pi pi-eye"
      message="No views yet. Add your first view."
    >
      <Button v-if="isAdmin" label="Add View" icon="pi pi-plus" @click="openCreate" />
    </EmptyState>

    <DataTable
      v-else
      :value="views"
      size="small"
      paginator
      :rows="25"
      :rowsPerPageOptions="[25, 50, 100]"
      sortField="name"
      :sortOrder="1"
      stripedRows
    >
      <Column field="name" header="Name" sortable />
      <Column field="description" header="Description" />
      <Column header="Providers">
        <template #body="{ data }">
          <div class="provider-tags">
            <Tag
              v-for="pid in data.provider_ids"
              :key="pid"
              :value="providerName(pid)"
              severity="secondary"
            />
            <span v-if="!data.provider_ids?.length" class="text-muted">None</span>
          </div>
        </template>
      </Column>
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
      :header="editingId ? 'Edit View' : 'Add View'"
      position="right"
      class="w-25rem"
    >
      <form @submit.prevent="handleSubmit" class="drawer-form">
        <div class="field">
          <label for="view-name">Name</label>
          <InputText id="view-name" v-model="form.name" class="w-full" />
        </div>
        <div class="field">
          <label for="view-desc">Description</label>
          <InputText id="view-desc" v-model="form.description" class="w-full" />
        </div>
        <div class="field">
          <label for="view-providers">Providers</label>
          <MultiSelect
            id="view-providers"
            v-model="form.providerIds"
            :options="allProviders"
            optionLabel="name"
            optionValue="id"
            placeholder="Select providers"
            class="w-full"
            display="chip"
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

.provider-tags {
  display: flex;
  flex-wrap: wrap;
  gap: 0.25rem;
}

.text-muted {
  color: var(--p-surface-400);
  font-size: 0.85rem;
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
