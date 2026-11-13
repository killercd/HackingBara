<script setup lang="ts">
import { computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import DataTable from './DataTable.vue'

const props = defineProps<{run: Record<string, any>}>()
const route = useRoute(), router = useRouter()
const tabs = ['subdomains', 'findings', 'events']
const tab = computed(() => tabs.includes(String(route.query.tab)) ? String(route.query.tab) : 'subdomains')
const metrics = [
  {key: 'subdomains', label: 'Discovered subdomains'},
  {key: 'errors', label: 'DNS errors'},
]
const fields: Record<string, {key: string, label: string}[]> = {
  subdomains: [
    {key: 'identity', label: 'Subdomain'},
    {key: 'evidence', label: 'IP addresses'},
    {key: 'created_at', label: 'Discovered at'},
  ],
  findings: [
    {key: 'kind', label: 'Kind'},
    {key: 'identity', label: 'Domain / subdomain'},
    {key: 'evidence', label: 'DNS evidence'},
    {key: 'created_at', label: 'Created at'},
  ],
  events: [
    {key: 'created_at', label: 'Time'},
    {key: 'level', label: 'Level'},
    {key: 'event_type', label: 'Event'},
    {key: 'message', label: 'Message'},
    {key: 'details', label: 'Details'},
  ],
}
const filters: Record<string, string[]> = {
  findings: ['subdomain', 'scanner_error'],
  events: ['info', 'warning', 'error'],
}
const refresh = computed(() => ['queued', 'running', 'pausing', 'stopping'].includes(props.run.status) ? 1500 : 0)
</script>

<template>
  <section class="panel" aria-label="DNS scan scope">
    <h2>DNS enumeration</h2>
    <p class="mono">{{run.config_snapshot.domain}}</p>
    <p class="muted">Gobuster DNS · {{run.config_snapshot.subdomains.length.toLocaleString()}} names in the selected wordlist</p>
    <p class="muted">{{run.config_snapshot.request_timeout ?? 2}} s per DNS lookup · {{run.config_snapshot.max_threads ?? 10}} threads · No total duration limit</p>
  </section>
  <div class="metrics">
    <div class="panel metric">
      <span>Wordlist entries</span>
      <strong>{{run.config_snapshot.subdomains.length.toLocaleString()}}</strong>
    </div>
    <div class="panel metric" v-for="metric in metrics" :key="metric.key">
      <span>{{metric.label}}</span>
      <strong>{{run.counts[metric.key] || 0}}</strong>
    </div>
  </div>
  <nav class="tabs" aria-label="Subdomain result sections">
    <button v-for="name in tabs" :key="name" :aria-current="tab===name?'page':undefined"
      :class="{active:tab===name}" @click="router.replace({query:{...route.query,tab:name}})">
      {{name[0].toUpperCase()+name.slice(1)}}
    </button>
  </nav>
  <DataTable :key="tab" :query-key="tab" :endpoint="`/runs/${run.id}/${tab}`"
    :columns="fields[tab]" :filter-status="tab!=='subdomains'" :status-options="filters[tab]" :refresh="refresh">
    <template #evidence="{value}">
      <span v-if="tab==='subdomains'">{{value.addresses.join(', ')}}</span>
      <span v-else>{{JSON.stringify(value)}}</span>
    </template>
  </DataTable>
</template>
