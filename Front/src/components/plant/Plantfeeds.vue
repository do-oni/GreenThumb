<template>
  <div style="float=center;">
     <div
        style="
          display: grid;
          grid-template-columns: 1fr 1fr;
          grid-template-rows: 1fr 1fr;
        "
      >
       <div class="card-body" v-for="(u, i) in myplants" :key="i">
        <div class="card border-Success  mb-3" style="max-width: 30rem">
          <p class="mb-3"></p>
         
            <router-link 
              :to="{
                name: 'Plantfeeddetail',
                params: { userId: u.userId, plantId: u.plantId },
                }" >
            <img
              style="width: 300px; height:250px"
              :src="u.imageUrl"
            />
            <p class="mb-3"></p>
            <p class="card-text">저는 {{ u.nickName }} 이에요.</p>
            <p class="mb-3"></p>
             </router-link>
          </div>
        </div>
      </div>
  </div>

</template>

<script>
import http from "@/util/http-common";
import { mapState } from "vuex";

export default {

  name: "Myprofile",

   data() {
    return {
      myplants: [],
      User: [],
      canRegister: true,
      canFollow: true,
    };
  },
  props: {
    userId: {},
    plantId: {},
  },
  computed: {
    ...mapState(["myplant"]),
    ...mapState(["userInfo"]),
  },

  watch: {
    $route(to, from) {
      if (to.path != from.path) {
        this.$router.go(this.$router.currentRoute);
      }
    },
  },
  created() {
    let token = localStorage.getItem("getToken");
    http
      .get("user/" + this.$route.params.userId + "/plants", {
        headers: { Authorization: `Bearer ${token}` },
      })
      .then((res) => {
        this.myplants = res.data;
      })
      .catch((err) => {
        console.log(err);
      })
      .then(() => {});

  },
};
</script>
<style>


</style>