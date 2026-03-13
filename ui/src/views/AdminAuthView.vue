<script setup lang="ts">
import { ref, computed, onMounted, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import DataTable from 'primevue/datatable'
import Column from 'primevue/column'
import Button from 'primevue/button'
import Drawer from 'primevue/drawer'
import Dialog from 'primevue/dialog'
import InputText from 'primevue/inputtext'
import Password from 'primevue/password'
import Textarea from 'primevue/textarea'
import MultiSelect from 'primevue/multiselect'
import ToggleSwitch from 'primevue/toggleswitch'
import Tag from 'primevue/tag'
import Checkbox from 'primevue/checkbox'
import Skeleton from 'primevue/skeleton'
import TabMenu from 'primevue/tabmenu'
import PageHeader from '../components/shared/PageHeader.vue'
import EmptyState from '../components/shared/EmptyState.vue'
import { useConfirmAction } from '../composables/useConfirm'
import { useNotificationStore } from '../stores/notification'
import * as userApi from '../api/users'
import * as groupApi from '../api/groups'
import * as roleApi from '../api/roles'
import type { UserDetail, Group, GroupDetail, Role, PermissionCategory } from '../types'

const route = useRoute()
const router = useRouter()
const notify = useNotificationStore()
const { confirmDelete } = useConfirmAction()

// ─── Tab Navigation ───
const tabs = [
  { label: 'Users', icon: 'pi pi-users', key: 'users' },
  { label: 'Groups', icon: 'pi pi-id-card', key: 'groups' },
  { label: 'Permissions', icon: 'pi pi-shield', key: 'permissions' },
]

const activeTab = ref(0)

// Sync tab from route query
function syncTabFromRoute() {
  const tab = route.query.tab as string
  const idx = tabs.findIndex(t => t.key === tab)
  activeTab.value = idx >= 0 ? idx : 0
}

watch(() => route.query.tab, syncTabFromRoute)

function onTabChange(e: { index: number }) {
  activeTab.value = e.index
  const tab = tabs[e.index]
  if (tab) router.replace({ query: { tab: tab.key } })
}

// ─── Users ───
const users = ref<UserDetail[]>([])
const usersLoading = ref(true)
const userDrawerVisible = ref(false)
const editingUserId = ref<number | null>(null)

const userCreateForm = ref({
  username: '',
  email: '',
  password: '',
  group_ids: [] as number[],
  force_password_change: true,
})

const userEditForm = ref({
  email: '',
  is_active: true,
  group_ids: [] as number[],
})

const resetDialogVisible = ref(false)
const resetUserId = ref<number | null>(null)
const resetPassword = ref('')

async function fetchUsers() {
  usersLoading.value = true
  try {
    const [u, g] = await Promise.all([userApi.listUsers(), groupApi.listGroups()])
    users.value = u
    groups.value = g
  } finally {
    usersLoading.value = false
  }
}

function openCreateUser() {
  editingUserId.value = null
  userCreateForm.value = { username: '', email: '', password: '', group_ids: [], force_password_change: true }
  userDrawerVisible.value = true
}

function openEditUser(user: UserDetail) {
  editingUserId.value = user.id
  userEditForm.value = {
    email: user.email,
    is_active: user.is_active,
    group_ids: user.groups.map(g => g.id),
  }
  userDrawerVisible.value = true
}

async function handleUserSubmit() {
  try {
    if (editingUserId.value !== null) {
      await userApi.updateUser(editingUserId.value, userEditForm.value)
      notify.success('User updated')
    } else {
      await userApi.createUser(userCreateForm.value)
      notify.success('User created')
    }
    userDrawerVisible.value = false
    await fetchUsers()
  } catch (e: any) {
    notify.error(e.message || 'Failed to save user')
  }
}

function handleDeleteUser(user: UserDetail) {
  confirmDelete(`Deactivate user "${user.username}"?`, async () => {
    try {
      await userApi.deleteUser(user.id)
      notify.success('User deactivated')
      await fetchUsers()
    } catch (e: any) {
      notify.error(e.message || 'Failed to deactivate user')
    }
  })
}

function openResetDialog(user: UserDetail) {
  resetUserId.value = user.id
  resetPassword.value = ''
  resetDialogVisible.value = true
}

async function handleResetPassword() {
  if (!resetUserId.value) return
  try {
    await userApi.resetPassword(resetUserId.value, resetPassword.value)
    notify.success('Password reset successfully')
    resetDialogVisible.value = false
  } catch (e: any) {
    notify.error(e.message || 'Failed to reset password')
  }
}

// ─── Groups ───
const groups = ref<Group[]>([])
const groupsLoading = ref(true)
const groupDrawerVisible = ref(false)
const editingGroupId = ref<number | null>(null)
const expandedGroupRows = ref({})
const groupDetails = ref<Map<number, GroupDetail>>(new Map())

const groupForm = ref({
  name: '',
  description: '',
})

async function fetchGroups() {
  groupsLoading.value = true
  try {
    groups.value = await groupApi.listGroups()
  } finally {
    groupsLoading.value = false
  }
}

function openCreateGroup() {
  editingGroupId.value = null
  groupForm.value = { name: '', description: '' }
  groupDrawerVisible.value = true
}

function openEditGroup(group: Group) {
  editingGroupId.value = group.id
  groupForm.value = { name: group.name, description: group.description }
  groupDrawerVisible.value = true
}

async function handleGroupSubmit() {
  try {
    if (editingGroupId.value !== null) {
      await groupApi.updateGroup(editingGroupId.value, groupForm.value)
      notify.success('Group updated')
    } else {
      await groupApi.createGroup(groupForm.value)
      notify.success('Group created')
    }
    groupDrawerVisible.value = false
    await fetchGroups()
  } catch (e: any) {
    notify.error(e.message || 'Failed to save group')
  }
}

function handleDeleteGroup(group: Group) {
  confirmDelete(`Delete group "${group.name}"?`, async () => {
    try {
      await groupApi.deleteGroup(group.id)
      notify.success('Group deleted')
      await fetchGroups()
    } catch (e: any) {
      notify.error(e.message || 'Failed to delete group')
    }
  })
}

async function onGroupRowExpand(event: any) {
  const id = event.data.id
  if (!groupDetails.value.has(id)) {
    try {
      const detail = await groupApi.getGroup(id)
      groupDetails.value.set(id, detail)
    } catch { /* ignore */ }
  }
}

function scopeLabel(scopeType?: string, scopeId?: number): string {
  if (!scopeType) return 'Global'
  return `${scopeType} #${scopeId}`
}

// ─── Permissions (Roles) ───
const roles = ref<Role[]>([])
const rolesLoading = ref(true)
const categories = ref<PermissionCategory[]>([])
const roleDrawerVisible = ref(false)
const editingRoleId = ref<number | null>(null)
const editingRoleIsSystem = ref(false)

const roleForm = ref({
  name: '',
  description: '',
})
const selectedPermissions = ref<string[]>([])

async function fetchRoles() {
  rolesLoading.value = true
  try {
    roles.value = await roleApi.listRoles()
  } finally {
    rolesLoading.value = false
  }
}

async function fetchCategories() {
  try {
    categories.value = await roleApi.listPermissionCategories()
  } catch { /* ignore */ }
}

function openCreateRole() {
  editingRoleId.value = null
  editingRoleIsSystem.value = false
  roleForm.value = { name: '', description: '' }
  selectedPermissions.value = []
  roleDrawerVisible.value = true
}

async function openEditRole(role: Role) {
  editingRoleId.value = role.id
  editingRoleIsSystem.value = role.is_system
  roleForm.value = { name: role.name, description: role.description }
  try {
    const perms = await roleApi.getRolePermissions(role.id)
    selectedPermissions.value = [...perms]
  } catch {
    selectedPermissions.value = []
  }
  roleDrawerVisible.value = true
}

async function handleRoleSubmit() {
  try {
    if (editingRoleId.value !== null) {
      await roleApi.updateRole(editingRoleId.value, {
        name: roleForm.value.name,
        description: roleForm.value.description,
      })
      await roleApi.setRolePermissions(editingRoleId.value, selectedPermissions.value)
      notify.success('Role updated')
    } else {
      await roleApi.createRole({
        name: roleForm.value.name,
        description: roleForm.value.description,
        permissions: selectedPermissions.value,
      })
      notify.success('Role created')
    }
    roleDrawerVisible.value = false
    await fetchRoles()
  } catch (e: any) {
    notify.error(e.message || 'Failed to save role')
  }
}

function handleDeleteRole(role: Role) {
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
      p => !cat.permissions.includes(p),
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

// ─── Tab-specific header actions ───
const tabTitle = computed(() => tabs[activeTab.value]?.label ?? 'Auth')
const tabSubtitle = computed(() => {
  switch (tabs[activeTab.value]?.key) {
    case 'users': return 'Manage user accounts'
    case 'groups': return 'Manage groups and membership'
    case 'permissions': return 'Manage roles and permissions'
    default: return ''
  }
})

// ─── Lifecycle ───
onMounted(() => {
  syncTabFromRoute()
  fetchUsers()
  fetchGroups()
  fetchRoles()
  fetchCategories()
})
</script>

<template>
  <div class="admin-auth-page">
    <PageHeader :title="tabTitle" :subtitle="tabSubtitle">
      <Button
        v-if="tabs[activeTab]?.key === 'users'"
        label="Add User"
        icon="pi pi-plus"
        @click="openCreateUser"
      />
      <Button
        v-if="tabs[activeTab]?.key === 'groups'"
        label="Add Group"
        icon="pi pi-plus"
        @click="openCreateGroup"
      />
      <Button
        v-if="tabs[activeTab]?.key === 'permissions'"
        label="Add Role"
        icon="pi pi-plus"
        @click="openCreateRole"
      />
    </PageHeader>

    <TabMenu :model="tabs" :activeIndex="activeTab" @tab-change="onTabChange" class="admin-tabs" />

    <!-- ═══ Users Tab ═══ -->
    <div v-if="tabs[activeTab]?.key === 'users'" class="tab-content">
      <div v-if="usersLoading" class="skeleton-table">
        <Skeleton v-for="i in 5" :key="i" height="2.5rem" class="mb-2" />
      </div>

      <EmptyState
        v-else-if="users.length === 0"
        icon="pi pi-users"
        message="No users found."
      >
        <Button label="Add User" icon="pi pi-plus" @click="openCreateUser" />
      </EmptyState>

      <DataTable
        v-else
        :value="users"
        size="small"
        paginator
        :rows="25"
        sortField="username"
        :sortOrder="1"
        stripedRows
      >
        <Column field="username" header="Username" sortable>
          <template #body="{ data }">
            <span class="font-mono">{{ data.username }}</span>
          </template>
        </Column>
        <Column field="email" header="Email" sortable />
        <Column field="auth_method" header="Auth" sortable>
          <template #body="{ data }">
            <Tag :value="data.auth_method" severity="secondary" />
          </template>
        </Column>
        <Column field="is_active" header="Active" sortable>
          <template #body="{ data }">
            <Tag :value="data.is_active ? 'Active' : 'Inactive'"
              :severity="data.is_active ? 'success' : 'danger'" />
          </template>
        </Column>
        <Column header="Groups">
          <template #body="{ data }">
            <Tag v-for="g in data.groups" :key="g.id" :value="g.name" severity="info" class="mr-1" />
          </template>
        </Column>
        <Column header="Actions" style="width: 8rem; text-align: right">
          <template #body="{ data }">
            <div class="action-buttons">
              <Button icon="pi pi-pencil" text rounded size="small" v-tooltip.top="'Edit'" @click="openEditUser(data)" />
              <Button icon="pi pi-key" text rounded size="small" v-tooltip.top="'Reset Password'" @click="openResetDialog(data)" />
              <Button icon="pi pi-trash" text rounded size="small" severity="danger" v-tooltip.top="'Deactivate'" @click="handleDeleteUser(data)" />
            </div>
          </template>
        </Column>
      </DataTable>
    </div>

    <!-- ═══ Groups Tab ═══ -->
    <div v-if="tabs[activeTab]?.key === 'groups'" class="tab-content">
      <div v-if="groupsLoading" class="skeleton-table">
        <Skeleton v-for="i in 5" :key="i" height="2.5rem" class="mb-2" />
      </div>

      <EmptyState
        v-else-if="groups.length === 0"
        icon="pi pi-users"
        message="No groups yet. Create your first group."
      >
        <Button label="Add Group" icon="pi pi-plus" @click="openCreateGroup" />
      </EmptyState>

      <DataTable
        v-else
        :value="groups"
        v-model:expandedRows="expandedGroupRows"
        dataKey="id"
        size="small"
        paginator
        :rows="25"
        sortField="name"
        :sortOrder="1"
        stripedRows
        @rowExpand="onGroupRowExpand"
      >
        <Column expander style="width: 3rem" />
        <Column field="name" header="Name" sortable>
          <template #body="{ data }">
            <span class="font-mono">{{ data.name }}</span>
          </template>
        </Column>
        <Column field="description" header="Description" />
        <Column field="member_count" header="Members" sortable style="width: 6rem" />
        <Column header="Actions" style="width: 6rem; text-align: right">
          <template #body="{ data }">
            <div class="action-buttons">
              <Button icon="pi pi-pencil" text rounded size="small" v-tooltip.top="'Edit'" @click="openEditGroup(data)" />
              <Button icon="pi pi-trash" text rounded size="small" severity="danger" v-tooltip.top="'Delete'" @click="handleDeleteGroup(data)" />
            </div>
          </template>
        </Column>
        <template #expansion="{ data }">
          <div class="expansion-content">
            <h4 class="expansion-title">Members</h4>
            <div v-if="groupDetails.get(data.id)?.members?.length" class="members-list">
              <div v-for="m in groupDetails.get(data.id)!.members" :key="`${m.user_id}-${m.role_id}`" class="member-row">
                <Tag :value="m.username" severity="secondary" />
                <Tag :value="m.role_name" severity="info" class="ml-1" />
                <Tag :value="scopeLabel(m.scope_type, m.scope_id)" severity="contrast" class="ml-1" />
              </div>
            </div>
            <span v-else class="text-surface-400 text-sm">No members</span>
          </div>
        </template>
      </DataTable>
    </div>

    <!-- ═══ Permissions Tab ═══ -->
    <div v-if="tabs[activeTab]?.key === 'permissions'" class="tab-content">
      <div v-if="rolesLoading" class="skeleton-table">
        <Skeleton v-for="i in 5" :key="i" height="2.5rem" class="mb-2" />
      </div>

      <EmptyState
        v-else-if="roles.length === 0"
        icon="pi pi-shield"
        message="No roles found."
      >
        <Button label="Add Role" icon="pi pi-plus" @click="openCreateRole" />
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
              <Button icon="pi pi-pencil" text rounded size="small" v-tooltip.top="'Edit'" @click="openEditRole(data)" />
              <Button
                icon="pi pi-trash"
                text rounded size="small"
                severity="danger"
                v-tooltip.top="'Delete'"
                :disabled="data.is_system"
                @click="handleDeleteRole(data)"
              />
            </div>
          </template>
        </Column>
      </DataTable>
    </div>

    <!-- ═══ User Drawer ═══ -->
    <Drawer v-model:visible="userDrawerVisible" :header="editingUserId ? 'Edit User' : 'Add User'" position="right" class="w-25rem">
      <form @submit.prevent="handleUserSubmit" class="drawer-form">
        <template v-if="editingUserId === null">
          <div class="field">
            <label>Username</label>
            <InputText v-model="userCreateForm.username" class="w-full" />
          </div>
          <div class="field">
            <label>Email</label>
            <InputText v-model="userCreateForm.email" class="w-full" />
          </div>
          <div class="field">
            <label>Password</label>
            <Password v-model="userCreateForm.password" :feedback="false" toggleMask class="w-full" inputClass="w-full" />
          </div>
          <div class="field">
            <label>Groups</label>
            <MultiSelect v-model="userCreateForm.group_ids" :options="groups" optionLabel="name" optionValue="id" class="w-full" placeholder="Select groups" />
          </div>
          <div class="field flex-row">
            <ToggleSwitch v-model="userCreateForm.force_password_change" />
            <label>Force password change on login</label>
          </div>
        </template>
        <template v-else>
          <div class="field">
            <label>Email</label>
            <InputText v-model="userEditForm.email" class="w-full" />
          </div>
          <div class="field flex-row">
            <ToggleSwitch v-model="userEditForm.is_active" />
            <label>Active</label>
          </div>
          <div class="field">
            <label>Groups</label>
            <MultiSelect v-model="userEditForm.group_ids" :options="groups" optionLabel="name" optionValue="id" class="w-full" placeholder="Select groups" />
          </div>
        </template>
        <Button type="submit" :label="editingUserId ? 'Save' : 'Create'" class="w-full" />
      </form>
    </Drawer>

    <!-- ═══ Reset Password Dialog ═══ -->
    <Dialog v-model:visible="resetDialogVisible" header="Reset Password" :style="{ width: '24rem' }" modal>
      <form @submit.prevent="handleResetPassword" class="drawer-form">
        <div class="field">
          <label>New Password</label>
          <Password v-model="resetPassword" :feedback="false" toggleMask class="w-full" inputClass="w-full" />
        </div>
        <small class="text-surface-400">User will be required to change password on next login.</small>
        <Button type="submit" label="Reset Password" class="w-full mt-3" />
      </form>
    </Dialog>

    <!-- ═══ Group Drawer ═══ -->
    <Drawer v-model:visible="groupDrawerVisible" :header="editingGroupId ? 'Edit Group' : 'Add Group'" position="right" class="w-25rem">
      <form @submit.prevent="handleGroupSubmit" class="drawer-form">
        <div class="field">
          <label>Name</label>
          <InputText v-model="groupForm.name" class="w-full" />
        </div>
        <div class="field">
          <label>Description</label>
          <Textarea v-model="groupForm.description" class="w-full" rows="3" />
        </div>
        <Button type="submit" :label="editingGroupId ? 'Save' : 'Create'" class="w-full" />
      </form>
    </Drawer>

    <!-- ═══ Role Drawer ═══ -->
    <Drawer v-model:visible="roleDrawerVisible" :header="editingRoleId ? 'Edit Role' : 'Add Role'" position="right" class="w-30rem">
      <form @submit.prevent="handleRoleSubmit" class="drawer-form">
        <div class="field">
          <label>Name</label>
          <InputText v-model="roleForm.name" class="w-full" :disabled="editingRoleIsSystem" />
        </div>
        <div class="field">
          <label>Description</label>
          <Textarea v-model="roleForm.description" class="w-full" rows="2" />
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

        <Button type="submit" :label="editingRoleId ? 'Save' : 'Create'" class="w-full" />
      </form>
    </Drawer>
  </div>
</template>

<style scoped>
.admin-auth-page {
  padding: 0;
}

.admin-tabs {
  margin-bottom: 1rem;
}

.tab-content {
  min-height: 20rem;
}

/* Shared utilities */
.skeleton-table { display: flex; flex-direction: column; gap: 0.5rem; }
.mb-2 { margin-bottom: 0.5rem; }
.mr-1 { margin-right: 0.25rem; }
.ml-1 { margin-left: 0.25rem; }
.ml-2 { margin-left: 0.5rem; }
.mt-3 { margin-top: 0.75rem; }
.text-surface-400 { color: var(--p-surface-400); }
.text-sm { font-size: 0.875rem; }
.font-mono { font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace; }
.action-buttons { display: flex; justify-content: flex-end; gap: 0.25rem; }
.drawer-form { display: flex; flex-direction: column; gap: 1rem; }
.field { display: flex; flex-direction: column; gap: 0.375rem; }
.field label { font-size: 0.875rem; font-weight: 500; }
.field.flex-row { flex-direction: row; align-items: center; gap: 0.5rem; }
.w-full { width: 100%; }
.w-25rem { width: 25rem; }
.w-30rem { width: 30rem; }

/* Group expansion */
.expansion-content { padding: 0.75rem 1rem; }
.expansion-title { font-size: 0.875rem; font-weight: 600; margin: 0 0 0.5rem; }
.members-list { display: flex; flex-direction: column; gap: 0.375rem; }
.member-row { display: flex; align-items: center; gap: 0.25rem; }

/* Permissions drawer */
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
