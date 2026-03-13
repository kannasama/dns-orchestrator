<script setup lang="ts">
import { onMounted, ref } from 'vue'
import DataTable from 'primevue/datatable'
import Column from 'primevue/column'
import Button from 'primevue/button'
import Drawer from 'primevue/drawer'
import InputText from 'primevue/inputtext'
import Textarea from 'primevue/textarea'
import Tag from 'primevue/tag'
import Checkbox from 'primevue/checkbox'
import Skeleton from 'primevue/skeleton'
import PageHeader from '../components/shared/PageHeader.vue'
import EmptyState from '../components/shared/EmptyState.vue'
import { useConfirmAction } from '../composables/useConfirm'
import { useNotificationStore } from '../stores/notification'
import * as roleApi from '../api/roles'
import type { Role, PermissionCategory } from '../types'

const notify = useNotificationStore()
const { confirmDelete } = useConfirmAction()

const roles = ref<Role[]>([])
const loading = ref(true)
const categories = ref<PermissionCategory[]>([])

const drawerVisible = ref(false)
const editingId = ref<number | null>(null)
const editingIsSystem = ref(false)

const form = ref({
  name: '',
  description: '',
})
const selectedPermissions = ref<string[]>([])

async function fetchRoles() {
  loading.value = true
  try {
    roles.value = await roleApi.listRoles()
  } finally {
    loading.value = false
  }
}

async function fetchCategories() {
  try {
    categories.value = await roleApi.listPermissionCategories()
  } catch { /* ignore */ }
}

function openCreate() {
  editingId.value = null
  editingIsSystem.value = false
  form.value = { name: '', description: '' }
  selectedPermissions.value = []
  drawerVisible.value = true
}

async function openEdit(role: Role) {
  editingId.value = role.id
  editingIsSystem.value = role.is_system
  form.value = { name: role.name, description: role.description }
  try {
    const perms = await roleApi.getRolePermissions(role.id)
    selectedPermissions.value = [...perms]
  } catch {
    selectedPermissions.value = []
  }
  drawerVisible.value = true
}

async function handleSubmit() {
  try {
    if (editingId.value !== null) {
      await roleApi.updateRole(editingId.value, {
        name: form.value.name,
        description: form.value.description,
      })
      await roleApi.setRolePermissions(editingId.value, selectedPermissions.value)
      notify.success('Role updated')
    } else {
      await roleApi.createRole({
        name: form.value.name,
        description: form.value.description,
        permissions: selectedPermissions.value,
      })
      notify.success('Role created')
    }
    drawerVisible.value = false
    await fetchRoles()
  } catch (e: any) {
    notify.error(e.message || 'Failed to save role')
  }
}

function handleDelete(role: Role) {
  confirmDelete(`Delete role "${role.name}"?`, async () => {
    try {
      await roleApi.deleteRole(role.id)
      notify.success('Role deleted')
      await fetchRoles()
    } catch (e: any) {
      notify.error(e.message || 'Failed to delete role')
    }
  })
}

function toggleCategory(cat: PermissionCategory) {
  const allSelected = cat.permissions.every(p => selectedPermissions.value.includes(p))
  if (allSelected) {
    selectedPermissions.value = selectedPermissions.value.filter(
      p => !cat.permissions.includes(p)
    )
  } else {
    const toAdd = cat.permissions.filter(p => !selectedPermissions.value.includes(p))
    selectedPermissions.value = [...selectedPermissions.value, ...toAdd]
  }
}

function isCategoryAllSelected(cat: PermissionCategory): boolean {
  return cat.permissions.every(p => selectedPermissions.value.includes(p))
}

function permLabel(perm: string): string {
  const dot = perm.indexOf('.')
  return dot >= 0 ? perm.substring(dot + 1) : perm
}

function permCount(role: Role): number {
  return role.permissions?.length ?? 0
}

onMounted(() => {
  fetchRoles()
  fetchCategories()
})
</script>

<template>
  <div>
    <PageHeader title="Roles" subtitle="Manage roles and permissions">
      <Button label="Add Role" icon="pi pi-plus" @click="openCreate" />
    </PageHeader>

    <div v-if="loading" class="skeleton-table">
      <Skeleton v-for="i in 5" :key="i" height="2.5rem" class="mb-2" />
    </div>

    <EmptyState
      v-else-if="roles.length === 0"
      icon="pi pi-shield"
      message="No roles found."
    >
      <Button label="Add Role" icon="pi pi-plus" @click="openCreate" />
    </EmptyState>

    <DataTable
      v-else
      :value="roles"
      dataKey="id"
      size="small"
      paginator
      :rows="25"
      sortField="name"
      :sortOrder="1"
      stripedRows
    >
      <Column field="name" header="Name" sortable>
        <template #body="{ data }">
          <span class="font-mono">{{ data.name }}</span>
          <Tag v-if="data.is_system" value="System" severity="secondary" class="ml-2" />
        </template>
      </Column>
      <Column field="description" header="Description" />
      <Column header="Permissions" sortable style="width: 8rem">
        <template #body="{ data }">
          {{ permCount(data) }}
        </template>
      </Column>
      <Column header="Actions" style="width: 6rem; text-align: right">
        <template #body="{ data }">
          <div class="action-buttons">
            <Button icon="pi pi-pencil" text rounded size="small" v-tooltip.top="'Edit'" @click="openEdit(data)" />
            <Button
              icon="pi pi-trash"
              text rounded size="small"
              severity="danger"
              v-tooltip.top="'Delete'"
              :disabled="data.is_system"
              @click="handleDelete(data)"
            />
          </div>
        </template>
      </Column>
    </DataTable>

    <Drawer v-model:visible="drawerVisible" :header="editingId ? 'Edit Role' : 'Add Role'" position="right" class="w-30rem">
      <form @submit.prevent="handleSubmit" class="drawer-form">
        <div class="field">
          <label>Name</label>
          <InputText v-model="form.name" class="w-full" :disabled="editingIsSystem" />
        </div>
        <div class="field">
          <label>Description</label>
          <Textarea v-model="form.description" class="w-full" rows="2" />
        </div>

        <div class="permissions-section">
          <label class="section-label">Permissions</label>
          <div v-for="cat in categories" :key="cat.name" class="perm-category">
            <div class="perm-category-header" @click="toggleCategory(cat)">
              <Checkbox
                :modelValue="isCategoryAllSelected(cat)"
                :binary="true"
                @click.stop="toggleCategory(cat)"
              />
              <span class="perm-category-name">{{ cat.name }}</span>
              <span class="perm-count">{{ cat.permissions.filter(p => selectedPermissions.includes(p)).length }}/{{ cat.permissions.length }}</span>
            </div>
            <div class="perm-grid">
              <label v-for="perm in cat.permissions" :key="perm" class="perm-item">
                <Checkbox
                  v-model="selectedPermissions"
                  :value="perm"
                />
                <span class="perm-label">{{ permLabel(perm) }}</span>
              </label>
            </div>
          </div>
        </div>

        <Button type="submit" :label="editingId ? 'Save' : 'Create'" class="w-full" />
      </form>
    </Drawer>
  </div>
</template>

<style scoped>
.skeleton-table { display: flex; flex-direction: column; gap: 0.5rem; }
.mb-2 { margin-bottom: 0.5rem; }
.ml-2 { margin-left: 0.5rem; }
.action-buttons { display: flex; justify-content: flex-end; gap: 0.25rem; }
.drawer-form { display: flex; flex-direction: column; gap: 1rem; }
.field { display: flex; flex-direction: column; gap: 0.375rem; }
.field label { font-size: 0.875rem; font-weight: 500; }
.w-full { width: 100%; }
.w-30rem { width: 30rem; }
.permissions-section { display: flex; flex-direction: column; gap: 0.75rem; }
.section-label { font-size: 0.875rem; font-weight: 600; }
.perm-category { border: 1px solid var(--p-surface-200); border-radius: 0.375rem; overflow: hidden; }
:root[class*="dark"] .perm-category { border-color: var(--p-surface-700); }
.perm-category-header {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.5rem 0.75rem;
  background: var(--p-surface-50);
  cursor: pointer;
  user-select: none;
}
:root[class*="dark"] .perm-category-header { background: var(--p-surface-800); }
.perm-category-name { font-weight: 500; font-size: 0.875rem; flex: 1; }
.perm-count { font-size: 0.75rem; color: var(--p-surface-500); }
.perm-grid {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 0.25rem 0.75rem;
  padding: 0.5rem 0.75rem;
}
.perm-item {
  display: flex;
  align-items: center;
  gap: 0.375rem;
  cursor: pointer;
  padding: 0.125rem 0;
}
.perm-label { font-size: 0.8125rem; font-family: var(--font-mono, monospace); }
</style>
