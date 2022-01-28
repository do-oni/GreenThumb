import Vue from "vue";
import Vuex from "vuex";
import router from "./router/router";
import http from "@/util/http-common";

Vue.use(Vuex);

export default new Vuex.Store({
  state: {
    userInfo: null,
    allUsers: [],
    isLogin: false,
    isLoginError: false,
  },
  mutations: {
    //로그인 성공시  /payload 뜻.전송되는 데이터
    loginSuccess(state, payload) {
      state.isLogin = true;
      state.isLoginError = false;
      state.userInfo = payload;
    },
    //로그인 실패시
    loginFail(state) {
      state.isLogin = false;
      state.isLoginError = true;
    },
    logouted(state) {
      state.isLogin = false;
      state.isLoginError = false;
      state.userInfo = null;
    },
  },
  getters: {
    loginCheck: function (state) {
      http
        .get("/user")
        .then((res) => {
          // console.log(res.data);
          return (state.allUsers = res.data);
        })
        .catch((err) => {
          console.log(err);
        })
        .then(() => {});
    },
  },
  // 행위 시도
  actions: {
    login({ dispatch }, loginObj) {
      let email = loginObj.email;
      let password = loginObj.password;

      //로그인 후 토큰 반환
      http
        .post("/auth/login", { email: email, password: password })
        .then((res) => {
          let token = res.data.accessToken;
          let id = res.data.userId;

          //일단 토큰 저장함
          localStorage.setItem("getToken", token);
          localStorage.setItem("getId", id);

          // sessionStorage.setItem("getToken",token)
          dispatch("getUserInfo");
          console.log('로그인 됐나')
          router.push({ name: "IndexMain" });
        });
    },
    getUserInfo({ commit }) {
      if (localStorage.getItem("getToken") !== null) {
        //토큰 -> 멤버 정보 반환 .. 토큰만 저장해두면 새로고침해도 사용가능 local storage에 저장하자. 밑에 새로 만든다.
        let token = localStorage.getItem("getToken");
        let id = localStorage.getItem("getId");

        http
          .get("/user/" + id + "/feed", { headers: { authorization: `Bearer ${token}` } })
          .then((response) => {
            console.log(response);
            let userInfo = {
              userId: id,
              email: response.data.email,
              nickName : response.data.nickName
            };
            
            commit("loginSuccess", userInfo);
          })
          .catch((error) => {
            console.log(error);
            alert("로그인을 실패했어요.");
          })
          .then(() => {});

      } else {
        commit("logouted");
      }
    },
    logout({ commit }) {
      
      let token = localStorage.getItem("getToken");
      let userId = localStorage.getItem("getId");
      http
        //delete("/auth/logout",  { headers: { Authorization: `Bearer ${token}` }})
        .post("http://13.125.110.238:8080/auth/logout/" + userId, {
          headers: { authorization: `Bearer ${token}` },
        })
        .then((res) => {
          console.log(res);
          alert("로그아웃 되었습니다.");
        })
        .catch((err) => {
          console.log(err);
        });
      localStorage.removeItem("getToken");
      localStorage.clear();
      commit("logouted");
      router.push({ name: "IndexMain" });
    }
  },
});
