<template>
    <nav class="navbar navbar-expand-lg bg-logInNav">
      <div class="navbar-collapse" id="navbarColor">
        <ul class="navbar-nav me-auto">
          <li class="nav-item">
            <a class="nav-link" href="/auth/login">
              <img src="../assets/images/user.png"  width="30" height="30">
            </a>
          </li>
          <li class="nav-item">
            <a class="nav-link" href="/auth/signup">
              <img src="../assets/images/signup.png"  width="25" height="23">
            </a>
          </li>
          <li class="nav-item">
            <a class="nav-link" href="/mypage">
              <img src="../assets/images/mypage.png"  width="35" height="33">
            </a>
          </li>
          <li class="nav-item">
            <a class="nav-link" href="/logout">
              <img src="../assets/images/logout.png"  width="40" height="33">
            </a>
          </li>
        </ul>
      </div>
    </nav>
</template>

<script>
import {mapActions, mapState} from 'vuex';

export default {
  name: "Header",
  data() {
    return {};
  },
  computed: {
    ...mapState(["isLogin"])
  },
  methods : {
    ...mapActions(["logout"])
  }
};
</script>

<style scoped>
/* 

#header-container {
  display: flex;
  justify-content: flex-end;
  align-items: center;
  width: 100%;
  min-width: 1130px;
  height: 50px;
  margin: 0 auto;
  background-color: black;
}

.headerBtn {
  float: right;
  text-align: center;
  margin: 0 auto;
  font-size: 100%;
  background-color: red;
  text-decoration: none;
}
*/

/* .header {
  float: right;
  margin: 0px;
  padding: 0px;
  color: black;
} */

/* .logIn {
  float: right;
  width: 100%;
} */

</style>
