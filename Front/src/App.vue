<template>
  <div>
    <!-- nav class에 navbar-dark 삭제함 -->
    <nav class="navbar navbar-expand-lg bg-logInNav">
      <div class="navbar-collapse" id="navbarColor">
        <ul class="navbar-nav me-auto" v-if="isLogin == false">
          <li class="nav-item">
            <a class="nav-link" href="/auth/login">
              <img src="./assets/images/user.png" width="30" height="30" />
            </a>
          </li>
          <li class="nav-item">
            <a class="nav-link" href="/auth/signup">
              <img src="./assets/images/signup.png" width="25" height="23" />
            </a>
          </li>
        </ul>
        <ul class="navbar-nav me-auto" v-else>
          <li class="nav-item">
            <a class="nav-link" href="/mypage">
              <img src="./assets/images/mypage.png" width="35" height="33" />
            </a>
          </li>
          <li class="nav-item" @click="logout">
            <a class="nav-link">
              <img src="./assets/images/logout.png" width="40" height="33" />
            </a>
          </li>
        </ul>
      </div>
    </nav>

    <div id="app">
      <nav class="navbar navbar-expand-lg navbar-dark bg-primary">
        <div class="container-fluid">
          <a class="navbar-brand" href="#">
            <!-- <img src="../src/assets/images/logo.png" alt=""> -->
          </a>
          <button
            class="navbar-toggler"
            type="button"
            data-bs-toggle="collapse"
            data-bs-target="#navbarColor01"
            aria-controls="navbarColor01"
            aria-expanded="false"
            aria-label="Toggle navigation"
          >
            <span class="navbar-toggler-icon"></span>
          </button>

          <div class="collapse navbar-collapse" id="navbarColor01">
            <ul class="navbar-nav me-auto">
              <li class="nav-item">
                <a class="nav-link active" href="/"
                  >홈
                  <span class="visually-hidden">(current)</span>
                </a>
              </li>
              <li class="nav-item">
                <router-link  :to="{ name: 'plant', params: { userId: userId} }" class="nav-link">내식물</router-link>
              </li>
              <li class="nav-item">
                 <router-link  :to="{ name: 'community', params: { userId: userId} }" class="nav-link">커뮤니티</router-link>
              </li>
              <li class="nav-item">
                <a class="nav-link" href="https://similarplant.netlify.app/">식물 MBTI</a>
              </li>
              <li class="nav-item">
                <a class="nav-link" href="/hospital">식물병원</a>
              </li>
              <li class="nav-item" v-if="isLogin">
                <router-link  :to="{ name: 'plantadd', params: { userId: this.userId} }" class="nav-link">식물등록</router-link>
              </li>
            </ul>
            <form class="d-flex">
              <input
                class="form-control me-sm-2"
                type="text"
                placeholder="어떤 식물들이 있을까요?"
                v-model="search"
              />
              <button class="btn btn-secondary my-2 my-sm-0"  @click="searchNaver">
                <img
                  src="./assets/images/natural.png"
                  width="30"
                  height="30"
                  style="filter: invert(100%)"
                />
              </button>
            </form>
          </div>
        </div>
      </nav>
      <br /><br />
      <div class="body">
        <br />
        <router-view />
      </div>
    </div>
  </div>
</template>

<script>
import { mapActions, mapState } from "vuex";

export default {
  name: "Header",
  data() {
    return {
      userId: localStorage.getItem("getId"),
      search: "",
    };
  },
  computed: {
    ...mapState(["isLogin"]),
    ...mapState(["userInfo"])

  },
  methods: {
    ...mapActions(["logout"]),
    searchNaver(){
      window.open("https://search.naver.com/search.naver?where=nexearch&sm=top_hty&fbm=1&ie=utf8&query="+this.search)
    }
  },
};
</script>

<style>
#app {
  font-family: Avenir, Helvetica, Arial, sans-serif;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
  text-align: center;
  color: #2c3e50;
}

#bar {
  padding: 30px;
  color: rgb(167, 82, 82);
}

#nav a.router-link-exact-active {
  color: #4297b9;
}

.body {
  width: 70%;
  min-height: 800px;
  margin-right: auto;
  margin-left: auto;
  background-color: white;
  /* border: 1px solid burlywood; */
  display: flex;
  flex-direction: column;
  align-items: center;
  word-break: break-all;
}
</style>
