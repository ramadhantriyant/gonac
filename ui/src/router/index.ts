import { createRouter, createWebHistory } from 'vue-router'
import DevicesView from '@/views/DevicesView.vue'

const router = createRouter({
  history: createWebHistory(import.meta.env.BASE_URL),
  routes: [
    {
      path: '/',
      name: 'devices',
      component: DevicesView,
    },
  ],
})

export default router
