<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import DataTable from './DataTable.vue'
import { api } from './api'
import { startScan } from './actions'
const route=useRoute(),router=useRouter(),scan=ref<Record<string,any>>(),error=ref(''),busy=ref(false)
onMounted(async()=>{try{scan.value=await api(`/scans/${route.params.id}`)}catch(e){error.value=(e as Error).message}})
async function start(){busy.value=true;try{const run=await startScan(String(route.params.id),scan.value!.target_summary);if(run)await router.push(`/scans/${route.params.id}/runs/${run.id}`)}catch(e){error.value=(e as Error).message}finally{busy.value=false}}
</script>
<template><p v-if="error" class="error" role="alert">{{error}}</p><template v-if="scan"><div class="page-heading"><div><p class="eyebrow">SCAN DEFINITION</p><h1>{{scan.name}}</h1><p class="muted">{{scan.description||'No description'}}</p></div><div class="actions"><RouterLink class="button subtle" :to="`/scans/${scan.id}/edit`">Edit configuration</RouterLink><button :disabled="busy" @click="start">Start new run</button></div></div><section class="panel"><h2>Authorized scope</h2><p class="mono">{{scan.target_summary}}</p><div class="actions"><span>Ports: {{scan.config.ports}}</span><span>· Screenshots: {{scan.config.screenshots?'on':'off'}}</span><span>· Credential validation: {{scan.config.password_spray?'on':'off'}}</span></div></section><h2>Run history</h2><DataTable :endpoint="`/scans/${scan.id}/runs`" :refresh="5000" filter-status :columns="[{key:'created_at',label:'Queued'},{key:'status',label:'Status'},{key:'current_stage',label:'Stage'},{key:'processed',label:'Processed targets'},{key:'started_at',label:'Started'},{key:'ended_at',label:'Ended'}]"><template #actions="{row}"><RouterLink class="button subtle" :to="`/scans/${scan.id}/runs/${row.id}`">Open results</RouterLink></template></DataTable></template></template>
