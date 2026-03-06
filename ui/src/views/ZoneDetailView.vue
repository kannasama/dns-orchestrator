<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import DataTable from 'primevue/datatable'
import Column from 'primevue/column'
import Button from 'primevue/button'
import Dialog from 'primevue/dialog'
import InputText from 'primevue/inputtext'
import InputNumber from 'primevue/inputnumber'
import Select from 'primevue/select'
import Skeleton from 'primevue/skeleton'
import Tag from 'primevue/tag'
import PageHeader from '../components/shared/PageHeader.vue'
import EmptyState from '../components/shared/EmptyState.vue'
import { useConfirmAction } from '../composables/useConfirm'
import { useRole } from '../composables/useRole'
import { useNotificationStore } from '../stores/notification'
import { ApiRequestError } from '../api/client'
import * as zoneApi from '../api/zones'
import * as recordApi from '../api/records'
import type { Zone, DnsRecord, RecordCreate } from '../types'

const route = useRoute()
const router = useRouter()
const { isOperator } = useRole()
const { confirmDelete } = useConfirmAction()
const notify = useNotificationStore()

const zoneId = Number(route.params.id)
const zone = ref<Zone | null>(null)
const records = ref<DnsRecord[]>([])
const loading = ref(true)

const dialogVisible = ref(false)
const editingRecordId = ref<number | null>(null)
const form = ref<RecordCreate>({
  name: '',
  type: 'A',
  ttl: 300,
  value_template: '',
  priority: 0,
})

const recordTypes = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'SRV', 'NS', 'PTR'].map((t) => ({
  label: t,
  value: t,
}))

async function fetchData() {
  loading.value = true
  try {
    const [z, r] = await Promise.all([zoneApi.getZone(zoneId), recordApi.listRecords(zoneId)])
    zone.value = z
    records.value = r
  } catch {
    notify.error('Failed to load zone')
  } finally {
    loading.value = false
  }
}

function openCreateRecord() {
  editingRecordId.value = null
  form.value = { name: '', type: 'A', ttl: 300, value_template: '', priority: 0 }
  dialogVisible.value = true
}

function openEditRecord(rec: DnsRecord) {
  editingRecordId.value = rec.id
  form.value = {
    name: rec.name,
    type: rec.type,
    ttl: rec.ttl,
    value_template: rec.value_template,
    priority: rec.priority,
  }
  dialogVisible.value = true
}

async function handleSubmitRecord() {
  try {
    if (editingRecordId.value !== null) {
      await recordApi.updateRecord(zoneId, editingRecordId.value, form.value)
      notify.success('Record updated')
    } else {
      await recordApi.createRecord(zoneId, form.value)
      notify.success('Record created')
    }
    dialogVisible.value = false
    await fetchData()
  } catch (err) {
    const msg = err instanceof ApiRequestError ? err.body.message : 'Failed to save record'
    notify.error('Error', msg)
  }
}

function handleDeleteRecord(rec: DnsRecord) {
  confirmDelete(`Delete record "${rec.name}" (${rec.type})?`, async () => {
    try {
      await recordApi.deleteRecord(zoneId, rec.id)
      notify.success('Record deleted')
      await fetchData()
    } catch (err) {
      const msg = err instanceof ApiRequestError ? err.body.message : 'Failed to delete'
      notify.error('Error', msg)
    }
  })
}

function goToDeploy() {
  router.push({ name: 'deployments', query: { zones: String(zoneId) } })
}

onMounted(fetchData)
</script>

<template>
  <div>
    <div v-if="loading">
      <Skeleton height="2rem" width="20rem" class="mb-2" />
      <Skeleton v-for="i in 5" :key="i" height="2.5rem" class="mb-2" />
    </div>

    <template v-else-if="zone">
      <PageHeader :title="zone.name" subtitle="Zone records">
        <Button
          v-if="isOperator"
          label="Deploy"
          icon="pi pi-play"
          severity="success"
          @click="goToDeploy"
          class="mr-2"
        />
        <Button
          v-if="isOperator"
          label="Add Record"
          icon="pi pi-plus"
          @click="openCreateRecord"
        />
      </PageHeader>

      <EmptyState
        v-if="records.length === 0"
        icon="pi pi-list"
        message="No records yet. Add your first DNS record."
      >
        <Button
          v-if="isOperator"
          label="Add Record"
          icon="pi pi-plus"
          @click="openCreateRecord"
        />
      </EmptyState>

      <DataTable
        v-else
        :value="records"
        size="small"
        paginator
        :rows="50"
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
        <Column field="type" header="Type" sortable style="width: 6rem">
          <template #body="{ data }">
            <Tag :value="data.type" severity="secondary" />
          </template>
        </Column>
        <Column field="value_template" header="Value">
          <template #body="{ data }">
            <span class="font-mono">{{ data.value_template }}</span>
          </template>
        </Column>
        <Column field="ttl" header="TTL" sortable style="width: 5rem">
          <template #body="{ data }">
            <span class="font-mono">{{ data.ttl }}</span>
          </template>
        </Column>
        <Column field="priority" header="Priority" sortable style="width: 5rem">
          <template #body="{ data }">
            <span class="font-mono">{{ data.priority }}</span>
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
                @click="openEditRecord(data)"
              />
              <Button
                icon="pi pi-trash"
                text
                rounded
                size="small"
                severity="danger"
                aria-label="Delete"
                v-tooltip.top="'Delete'"
                @click="handleDeleteRecord(data)"
              />
            </div>
          </template>
        </Column>
      </DataTable>
    </template>

    <Dialog
      v-model:visible="dialogVisible"
      :header="editingRecordId ? 'Edit Record' : 'Add Record'"
      modal
      class="w-30rem"
    >
      <form @submit.prevent="handleSubmitRecord" class="dialog-form">
        <div class="field">
          <label for="rec-name">Name</label>
          <InputText id="rec-name" v-model="form.name" class="w-full" placeholder="@" />
        </div>
        <div class="field">
          <label for="rec-type">Type</label>
          <Select
            id="rec-type"
            v-model="form.type"
            :options="recordTypes"
            optionLabel="label"
            optionValue="value"
            class="w-full"
          />
        </div>
        <div class="field">
          <label for="rec-value">Value Template</label>
          <InputText
            id="rec-value"
            v-model="form.value_template"
            class="w-full font-mono"
            placeholder="192.168.1.1 or {{my_var}}"
          />
        </div>
        <div class="form-row">
          <div class="field flex-1">
            <label for="rec-ttl">TTL</label>
            <InputNumber id="rec-ttl" v-model="form.ttl" :min="1" :max="604800" class="w-full" />
          </div>
          <div class="field flex-1">
            <label for="rec-priority">Priority</label>
            <InputNumber id="rec-priority" v-model="form.priority" :min="0" class="w-full" />
          </div>
        </div>
        <Button type="submit" :label="editingRecordId ? 'Save' : 'Create'" class="w-full" />
      </form>
    </Dialog>
  </div>
</template>

<style scoped>
.mb-2 {
  margin-bottom: 0.5rem;
}

.mr-2 {
  margin-right: 0.5rem;
}

.action-buttons {
  display: flex;
  justify-content: flex-end;
  gap: 0.25rem;
}

.dialog-form {
  display: flex;
  flex-direction: column;
  gap: 1rem;
}

.form-row {
  display: flex;
  gap: 1rem;
}

.flex-1 {
  flex: 1;
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

.w-30rem {
  width: 30rem;
}
</style>
