<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import DataTable from 'primevue/datatable'
import Column from 'primevue/column'
import Button from 'primevue/button'
import Dialog from 'primevue/dialog'
import InputText from 'primevue/inputtext'
import Textarea from 'primevue/textarea'
import Select from 'primevue/select'
import InputSwitch from 'primevue/toggleswitch'
import Tag from 'primevue/tag'
import Message from 'primevue/message'
import PageHeader from '../components/shared/PageHeader.vue'
import { useConfirmAction } from '../composables/useConfirm'
import { useNotificationStore } from '../stores/notification'
import type { IdentityProvider, GroupMappingRule } from '../types'
import * as idpApi from '../api/identityProviders'
import { listGroups } from '../api/groups'
import { listSettings } from '../api/settings'

const notify = useNotificationStore()
const { confirmDelete } = useConfirmAction()

const items = ref<IdentityProvider[]>([])
const loading = ref(false)
const dialogVisible = ref(false)
const isEditing = ref(false)

const groups = ref<{ id: number; name: string }[]>([])

// Base URL for auto-generating callback URLs
const baseUrl = ref('')
const baseUrlConfigured = ref(false)

const computedBaseUrl = computed(() => {
  if (baseUrl.value) return baseUrl.value
  // Fallback: derive from current browser URL
  return `${window.location.protocol}//${window.location.host}`
})

function oidcRedirectUri(idpId?: number) {
  if (idpId) return `${computedBaseUrl.value}/api/v1/auth/oidc/${idpId}/callback`
  return `${computedBaseUrl.value}/api/v1/auth/oidc/{id}/callback`
}
function samlAcsUrl(idpId?: number) {
  if (idpId) return `${computedBaseUrl.value}/api/v1/auth/saml/${idpId}/acs`
  return `${computedBaseUrl.value}/api/v1/auth/saml/{id}/acs`
}

// Form state
const form = ref({
  id: 0,
  name: '',
  type: 'oidc' as 'oidc' | 'saml',
  is_enabled: true,
  // OIDC fields
  issuer_url: '',
  client_id: '',
  client_secret: '',
  scopes: 'openid email profile',
  groups_claim: 'groups',
  // SAML fields
  entity_id: '',
  sso_url: '',
  certificate: '',
  name_id_format: '',
  group_attribute: 'groups',
  // Group mappings
  mappingRules: [] as GroupMappingRule[],
  default_group_id: null as number | null,
})

const typeOptions = [
  { label: 'OIDC', value: 'oidc' },
  { label: 'SAML', value: 'saml' },
]

async function fetchData() {
  loading.value = true
  try {
    const [idps, allGroups, settings] = await Promise.all([
      idpApi.listIdentityProviders(),
      listGroups(),
      listSettings(),
    ])
    items.value = idps
    groups.value = allGroups.map((g: { id: number; name: string }) => ({
      id: g.id,
      name: g.name,
    }))

    // Extract base URL from settings
    const baseUrlSetting = settings.find(s => s.key === 'app.base_url')
    if (baseUrlSetting && baseUrlSetting.value) {
      baseUrl.value = baseUrlSetting.value.replace(/\/$/, '') // strip trailing slash
      baseUrlConfigured.value = true
    } else {
      baseUrl.value = ''
      baseUrlConfigured.value = false
    }
  } finally {
    loading.value = false
  }
}

onMounted(fetchData)

function openCreate() {
  isEditing.value = false
  form.value = {
    id: 0,
    name: '',
    type: 'oidc',
    is_enabled: true,
    issuer_url: '',
    client_id: '',
    client_secret: '',
    scopes: 'openid email profile',
    groups_claim: 'groups',
    entity_id: '',
    sso_url: '',
    certificate: '',
    name_id_format: '',
    group_attribute: 'groups',
    mappingRules: [],
    default_group_id: null,
  }
  dialogVisible.value = true
}

function openEdit(idp: IdentityProvider) {
  isEditing.value = true
  const cfg = idp.config as Record<string, string>
  form.value = {
    id: idp.id,
    name: idp.name,
    type: idp.type,
    is_enabled: idp.is_enabled,
    issuer_url: cfg.issuer_url ?? '',
    client_id: cfg.client_id ?? '',
    client_secret: '',
    scopes: Array.isArray(cfg.scopes)
      ? (cfg.scopes as unknown as string[]).join(' ')
      : (cfg.scopes ?? 'openid email profile'),
    groups_claim: cfg.groups_claim ?? 'groups',
    entity_id: cfg.entity_id ?? '',
    sso_url: cfg.sso_url ?? '',
    certificate: cfg.certificate ?? '',
    name_id_format: cfg.name_id_format ?? '',
    group_attribute: cfg.group_attribute ?? 'groups',
    mappingRules: idp.group_mappings?.rules ?? [],
    default_group_id: idp.default_group_id,
  }
  dialogVisible.value = true
}

function buildConfig() {
  if (form.value.type === 'oidc') {
    return {
      issuer_url: form.value.issuer_url,
      client_id: form.value.client_id,
      redirect_uri: oidcRedirectUri(form.value.id),
      scopes: form.value.scopes.split(/\s+/).filter(Boolean),
      groups_claim: form.value.groups_claim,
    }
  }
  return {
    entity_id: form.value.entity_id,
    sso_url: form.value.sso_url,
    certificate: form.value.certificate,
    assertion_consumer_service_url: samlAcsUrl(form.value.id),
    name_id_format: form.value.name_id_format,
    group_attribute: form.value.group_attribute,
  }
}

async function save() {
  try {
    const config = buildConfig()
    const mappings =
      form.value.mappingRules.length > 0
        ? { rules: form.value.mappingRules }
        : undefined

    if (isEditing.value) {
      await idpApi.updateIdentityProvider(form.value.id, {
        name: form.value.name,
        is_enabled: form.value.is_enabled,
        config,
        client_secret: form.value.client_secret || undefined,
        group_mappings: mappings,
        default_group_id: form.value.default_group_id ?? undefined,
      })
      notify.success('Identity provider updated')
    } else {
      await idpApi.createIdentityProvider({
        name: form.value.name,
        type: form.value.type,
        config,
        client_secret: form.value.client_secret || undefined,
        group_mappings: mappings,
        default_group_id: form.value.default_group_id ?? undefined,
      })
      notify.success('Identity provider created')
    }
    dialogVisible.value = false
    await fetchData()
  } catch (err: unknown) {
    notify.error((err as Error).message || 'Failed to save')
  }
}

async function handleDelete(idp: IdentityProvider) {
  confirmDelete(
    `Delete identity provider "${idp.name}"?`,
    async () => {
      await idpApi.deleteIdentityProvider(idp.id)
      notify.success('Identity provider deleted')
      await fetchData()
    },
  )
}

async function handleTest(idp: IdentityProvider) {
  try {
    const result = await idpApi.testIdentityProvider(idp.id)
    window.open(result.redirect_url, '_blank', 'width=600,height=700')
  } catch (err: unknown) {
    notify.error((err as Error).message || 'Test failed')
  }
}

function addMappingRule() {
  form.value.mappingRules.push({ idp_group: '', meridian_group_id: 0 })
}

function removeMappingRule(index: number) {
  form.value.mappingRules.splice(index, 1)
}

function typeSeverity(type: string) {
  return type === 'oidc' ? 'info' : 'warn'
}

const groupOptions = computed(() =>
  groups.value.map((g) => ({ label: g.name, value: g.id })),
)

function copyToClipboard(text: string) {
  navigator.clipboard.writeText(text)
  notify.success('Copied to clipboard')
}
</script>

<template>
  <div>
    <PageHeader title="Identity Providers" subtitle="Configure external authentication">
      <Button label="Add Provider" icon="pi pi-plus" @click="openCreate" />
    </PageHeader>

    <Message v-if="!baseUrlConfigured" severity="warn" :closable="false" class="mb-3">
      <strong>app.base_url</strong> is not configured. Callback URLs are being derived from your
      current browser URL (<code>{{ computedBaseUrl }}</code>). Set <code>app.base_url</code> in
      <router-link to="/admin/settings">Settings</router-link> or the <code>DNS_BASE_URL</code>
      environment variable for reliable IdP configuration.
    </Message>

    <DataTable :value="items" :loading="loading" stripedRows>
      <Column field="name" header="Name" sortable />
      <Column field="type" header="Type" sortable>
        <template #body="{ data }">
          <Tag :value="data.type.toUpperCase()" :severity="typeSeverity(data.type)" />
        </template>
      </Column>
      <Column field="is_enabled" header="Enabled">
        <template #body="{ data }">
          <i
            :class="data.is_enabled ? 'pi pi-check-circle' : 'pi pi-times-circle'"
            :style="{ color: data.is_enabled ? 'var(--p-green-400)' : 'var(--p-red-400)' }"
          />
        </template>
      </Column>
      <Column header="Callback URL">
        <template #body="{ data }">
          <code class="callback-url">{{ data.type === 'oidc' ? oidcRedirectUri(data.id) : samlAcsUrl(data.id) }}</code>
        </template>
      </Column>
      <Column header="Actions" style="width: 12rem">
        <template #body="{ data }">
          <div class="flex gap-2">
            <Button
              icon="pi pi-play"
              severity="info"
              text
              rounded
              size="small"
              v-tooltip="'Test'"
              @click="handleTest(data)"
            />
            <Button
              icon="pi pi-pencil"
              severity="secondary"
              text
              rounded
              size="small"
              @click="openEdit(data)"
            />
            <Button
              icon="pi pi-trash"
              severity="danger"
              text
              rounded
              size="small"
              @click="handleDelete(data)"
            />
          </div>
        </template>
      </Column>
    </DataTable>

    <Dialog
      v-model:visible="dialogVisible"
      :header="isEditing ? 'Edit Identity Provider' : 'Add Identity Provider'"
      modal
      :style="{ width: '44rem' }"
    >
      <div class="idp-form">
        <div class="form-grid">
          <div class="field">
            <label>Name</label>
            <InputText v-model="form.name" class="w-full" />
          </div>

          <div class="field" v-if="!isEditing">
            <label>Type</label>
            <Select
              v-model="form.type"
              :options="typeOptions"
              optionLabel="label"
              optionValue="value"
              class="w-full"
            />
          </div>

          <div class="field" v-if="isEditing">
            <label>Enabled</label>
            <InputSwitch v-model="form.is_enabled" />
          </div>
        </div>

        <!-- OIDC Config -->
        <template v-if="form.type === 'oidc'">
          <h4 class="form-section-title">OIDC Configuration</h4>

          <!-- Auto-generated Redirect URI -->
          <div class="callback-display">
            <label>Redirect URI</label>
            <div class="callback-value">
              <code>{{ oidcRedirectUri(form.id) }}</code>
              <Button
                icon="pi pi-copy"
                text
                rounded
                size="small"
                v-tooltip="'Copy'"
                @click="copyToClipboard(oidcRedirectUri(form.id))"
              />
            </div>
            <small class="callback-hint">
              Configure this URL in your identity provider's OAuth/OIDC settings.
            </small>
          </div>

          <div class="form-grid">
            <div class="field">
              <label>Issuer URL</label>
              <InputText v-model="form.issuer_url" class="w-full" placeholder="https://accounts.google.com" />
            </div>
            <div class="field">
              <label>Client ID</label>
              <InputText v-model="form.client_id" class="w-full" />
            </div>
            <div class="field">
              <label>Client Secret</label>
              <InputText
                v-model="form.client_secret"
                type="password"
                class="w-full"
                :placeholder="isEditing ? '(unchanged)' : ''"
              />
            </div>
            <div class="field">
              <label>Scopes</label>
              <InputText v-model="form.scopes" class="w-full" placeholder="openid email profile" />
            </div>
            <div class="field">
              <label>Groups Claim</label>
              <InputText v-model="form.groups_claim" class="w-full" placeholder="groups" />
            </div>
          </div>
        </template>

        <!-- SAML Config -->
        <template v-if="form.type === 'saml'">
          <h4 class="form-section-title">SAML Configuration</h4>

          <!-- Auto-generated ACS URL -->
          <div class="callback-display">
            <label>Assertion Consumer Service (ACS) URL</label>
            <div class="callback-value">
              <code>{{ samlAcsUrl(form.id) }}</code>
              <Button
                icon="pi pi-copy"
                text
                rounded
                size="small"
                v-tooltip="'Copy'"
                @click="copyToClipboard(samlAcsUrl(form.id))"
              />
            </div>
            <small class="callback-hint">
              Configure this URL in your SAML identity provider settings.
            </small>
          </div>

          <div class="form-grid">
            <div class="field">
              <label>SP Entity ID</label>
              <InputText v-model="form.entity_id" class="w-full" />
            </div>
            <div class="field">
              <label>IdP SSO URL</label>
              <InputText v-model="form.sso_url" class="w-full" />
            </div>
          </div>
          <div class="field">
            <label>IdP Certificate (PEM)</label>
            <Textarea v-model="form.certificate" class="w-full" rows="4" />
          </div>
          <div class="field">
            <label>Group Attribute</label>
            <InputText v-model="form.group_attribute" class="w-full" placeholder="groups" />
          </div>
        </template>

        <!-- Group Mapping Rules -->
        <div class="mapping-section">
          <div class="flex items-center justify-between mb-2">
            <label class="font-semibold">Group Mapping Rules</label>
            <Button label="Add Rule" icon="pi pi-plus" size="small" text @click="addMappingRule" />
          </div>
          <p class="text-sm text-surface-400 mb-2">
            Map IdP groups to Meridian groups. Use * as a wildcard suffix (e.g. platform-*).
          </p>
          <div v-for="(rule, idx) in form.mappingRules" :key="idx" class="flex gap-2 mb-2 items-center">
            <InputText v-model="rule.idp_group" placeholder="IdP Group" class="flex-1" />
            <Select
              v-model="rule.meridian_group_id"
              :options="groupOptions"
              optionLabel="label"
              optionValue="value"
              placeholder="Meridian Group"
              class="flex-1"
            />
            <Button icon="pi pi-times" severity="danger" text rounded size="small" @click="removeMappingRule(idx)" />
          </div>
        </div>

        <div class="field">
          <label>Default Group</label>
          <Select
            v-model="form.default_group_id"
            :options="groupOptions"
            optionLabel="label"
            optionValue="value"
            placeholder="None"
            showClear
            class="w-full"
          />
        </div>
      </div>

      <template #footer>
        <Button label="Cancel" severity="secondary" text @click="dialogVisible = false" />
        <Button :label="isEditing ? 'Update' : 'Create'" @click="save" />
      </template>
    </Dialog>
  </div>
</template>

<style scoped>
.mb-3 { margin-bottom: 0.75rem; }

.idp-form {
  display: flex;
  flex-direction: column;
  gap: 1rem;
}

.form-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 1rem;
}

.form-section-title {
  font-size: 0.9375rem;
  font-weight: 600;
  margin: 0.5rem 0 0;
  padding-bottom: 0.5rem;
  border-bottom: 1px solid var(--p-surface-700);
  color: var(--p-surface-200);
}

:root:not(.app-dark) .form-section-title {
  border-bottom-color: var(--p-surface-200);
  color: var(--p-surface-800);
}

.field {
  display: flex;
  flex-direction: column;
  gap: 0.375rem;
}

.field label {
  font-size: 0.875rem;
  font-weight: 500;
  color: var(--p-surface-300);
}

:root:not(.app-dark) .field label {
  color: var(--p-surface-600);
}

/* Callback URL display */
.callback-display {
  background: var(--p-surface-800);
  border: 1px solid var(--p-surface-700);
  border-radius: 0.5rem;
  padding: 0.75rem 1rem;
  display: flex;
  flex-direction: column;
  gap: 0.375rem;
}

:root:not(.app-dark) .callback-display {
  background: var(--p-surface-50);
  border-color: var(--p-surface-200);
}

.callback-display label {
  font-size: 0.8125rem;
  font-weight: 600;
  color: var(--p-surface-300);
}

:root:not(.app-dark) .callback-display label {
  color: var(--p-surface-600);
}

.callback-value {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.callback-value code {
  font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace;
  font-size: 0.8125rem;
  color: var(--p-primary-400);
  word-break: break-all;
}

:root:not(.app-dark) .callback-value code {
  color: var(--p-primary-600);
}

.callback-hint {
  font-size: 0.75rem;
  color: var(--p-surface-500);
}

.callback-url {
  font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace;
  font-size: 0.75rem;
  color: var(--p-surface-400);
}

.mapping-section {
  border: 1px solid var(--p-surface-700);
  border-radius: 0.375rem;
  padding: 1rem;
}

:root:not(.app-dark) .mapping-section {
  border-color: var(--p-surface-200);
}
</style>
