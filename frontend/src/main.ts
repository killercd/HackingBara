import { createApp } from 'vue'
import { createRouter, createWebHistory } from 'vue-router'
import App from './App.vue'
import Login from './Login.vue'
import Scans from './Scans.vue'
import ScanForm from './ScanForm.vue'
import ScanDetail from './ScanDetail.vue'
import Run from './Run.vue'
import Credentials from './Credentials.vue'
import { api } from './api'
import './style.css'
const router = createRouter({history:createWebHistory(),routes:[
  {path:'/',redirect:'/scans'}, {path:'/login',component:Login},
  {path:'/scans',component:Scans}, {path:'/scans/new',component:ScanForm},
  {path:'/scans/:id/edit',component:ScanForm}, {path:'/scans/:id',component:ScanDetail},
  {path:'/scans/:id/runs/:runId',component:Run}, {path:'/credentials',component:Credentials},
  {path:'/:pathMatch(.*)*',redirect:'/scans'}]})
router.beforeEach(async to=>{
  if(to.path==='/login') return true
  try {await api('/auth/me'); return true} catch {return '/login'}
})
createApp(App).use(router).mount('#app')
