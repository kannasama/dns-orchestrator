<script setup lang="ts">
defineProps<{
  title: string
  subtitle?: string
}>()
</script>

<template>
  <div class="page-header">
    <div>
      <h1 class="page-title">{{ title }}</h1>
      <p v-if="subtitle" class="page-subtitle">{{ subtitle }}</p>
    </div>
    <div class="page-actions">
      <slot />
    </div>
  </div>
</template>

<style scoped>
.page-header {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  margin-bottom: 1rem;
}

.page-title {
  font-size: 1.5rem;
  font-weight: 700;
  margin: 0;
  color: var(--p-surface-0);
}

:root:not(.app-dark) .page-title {
  color: var(--p-surface-900);
}

.page-subtitle {
  font-size: 0.875rem;
  color: var(--p-surface-400);
  margin: 0.25rem 0 0;
}

:root:not(.app-dark) .page-subtitle {
  color: var(--p-surface-500);
}

.page-actions {
  display: flex;
  gap: 0.5rem;
}
</style>
