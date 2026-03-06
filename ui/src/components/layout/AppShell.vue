<script setup lang="ts">
import AppTopBar from './AppTopBar.vue'
import AppSidebar from './AppSidebar.vue'
</script>

<template>
  <div class="app-shell">
    <AppTopBar />
    <div class="app-body">
      <AppSidebar />
      <main class="app-content">
        <router-view />
      </main>
    </div>
  </div>
</template>

<style scoped>
.app-shell {
  display: flex;
  flex-direction: column;
  min-height: 100vh;
}

.app-body {
  display: flex;
  flex: 1;
}

.app-content {
  flex: 1;
  padding: 1rem 1.5rem;
  background: var(--p-surface-950);
  overflow-y: auto;
}

:root:not(.app-dark) .app-content {
  background: var(--p-surface-0);
}
</style>
