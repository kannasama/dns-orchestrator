import { createApp } from 'vue'
import { createPinia } from 'pinia'
import PrimeVue from 'primevue/config'
import ConfirmationService from 'primevue/confirmationservice'
import ToastService from 'primevue/toastservice'
import { themeConfig } from './theme'
import router from './router'
import App from './App.vue'

import 'primeicons/primeicons.css'
import './style.css'

const app = createApp(App)

app.use(createPinia())
app.use(router)
app.use(PrimeVue, { theme: themeConfig })
app.use(ConfirmationService)
app.use(ToastService)

app.mount('#app')
