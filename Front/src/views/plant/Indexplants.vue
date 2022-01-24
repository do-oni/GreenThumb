<template>
  <div class="contents">
    <Myprofile />
    <hr />
    <Plantfeed />
  </div>
</template>
<script>
import Myprofile from "../../components/plant/Myprofiles.vue";
import Plantfeed from "../../components/plant/Plantfeeds.vue";
export default {
  name: "plant",
  components: {
    Myprofile,
    Plantfeed,
  },
};
</script>
<style>
</style>