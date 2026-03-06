<script setup lang="ts">
import { watch } from 'vue'
import Toast from 'primevue/toast'
import ConfirmDialog from 'primevue/confirmdialog'
import { useToast } from 'primevue/usetoast'
import { useNotificationStore } from './stores/notification'

const toast = useToast()
const notify = useNotificationStore()

watch(
  () => notify.messages.length,
  () => {
    while (notify.messages.length > 0) {
      const msg = notify.messages.shift()!
      toast.add(msg)
    }
  },
)
</script>

<template>
  <Toast position="bottom-right" />
  <ConfirmDialog />
  <router-view />
</template>
