<script setup lang="ts">
import { useRoute, useRouter } from 'vue-router'
import { ref } from 'vue'
import { api } from './api'
const route=useRoute(), router=useRouter(), error=ref('')
async function logout(){try{await api('/auth/logout','POST');await router.push('/login')}catch(e){error.value=(e as Error).message}}
</script>
<template>
  <header><RouterLink class="brand" to="/scans" aria-label="HackingBara — Scans"><img class="brand-icon" src="/capbar.png" alt="" width="48" height="48"><img class="brand-wordmark" src="/hackingbara-wordmark.svg" alt="HackingBara" width="218" height="46"><small>ASSESSMENT WORKSPACE</small></RouterLink>
    <nav v-if="route.path!='/login'" aria-label="Main navigation"><RouterLink to="/scans">Scans</RouterLink><RouterLink to="/credentials">Credentials</RouterLink><button class="subtle" @click="logout">Sign out</button></nav>
  </header>
  <main><p v-if="error" class="error" role="alert">{{error}}</p><RouterView :key="route.path"/></main>
  <footer>HackingBara · Authorized scope. Observable execution.</footer>
</template>
