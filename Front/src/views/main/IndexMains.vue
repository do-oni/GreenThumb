<template>
  <div>
    <div class="input-group mb-3">
      <span>
        <input
          type="text"
          style="width: 300px; margin: 0px 0px 0 35px"
          class="form-control"
          v-model="search"
          placeholder="검색어를 입력해주세요."
      /></span>
      <button class="btn btn-primary" type="button" id="button-addon2">
        검색
      </button>
    </div>
    <div style="text-align: left; margin: 0px 0px 0 35px">
      <span class="badge bg-primary">선인장🌵 </span>&nbsp;
      <span class="badge bg-secondary">무궁화🌺</span>&nbsp;<br>
      <span class="badge bg-success">식물mbti🍒</span>&nbsp;
      <span class="badge bg-danger">병원가기💊</span>&nbsp;
      <span class="badge bg-warning">전체</span>
    </div>
    <br>
    <ul style="display: flex; flex-wrap: wrap; gap: 10px">
      <div
        class="card border-primary mb-3"
        style="max-width: 20rem; border: none"
        v-for="(u, i) in filterData"
        :key="i"
      >
        <router-link
          :to="{
            name: 'Plantfeeddetail',
            params: { userId: u.userId, plantId: u.plantId },
          }"
        >
          <div class="card-header">
            <img :src="u.imageUrl" class="imgSize" />
          </div>
          <div class="card-body">
            <p class="card-title">{{ u.nickName }}</p>
          </div>
        </router-link>
      </div>
    </ul>
  </div>
</template>

<script>
import http from "@/util/http-common";
import { mapState } from "vuex";

export default {
  name: "IndexMain",
  data() {
    return {
      search: "",
      allPlant: [],
      isRouterAlive: true,
    };
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
      .get("/plants", { headers: { Authorization: `Bearer ${token}` } })
      .then((res) => {
        this.allPlant = res.data;
      })
      .catch((err) => {
        console.log(err);
      })
      .then(() => {});
  },
  methods: {
    reload: function () {
      this.isRouterAlive = false;
      setTimeout(() => {
        this.isRouterAlive = true;
      }, 0);
    },
  },
  computed: {
    ...mapState(["myplant"]),
    ...mapState(["userInfo"]),

    filterData() {
      return this.allPlant.filter((e) => e.name.indexOf(this.search) >= 0);
    },
  },
};
</script>

<style>
.imgSize {
  width: 180px;
  height: 180px;
  vertical-align: center;
  padding: 10px 10px 10px 10px;
  border-radius: 15px;
}
</style>
