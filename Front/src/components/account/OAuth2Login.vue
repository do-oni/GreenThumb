<template>
  <div style="text-align: center;">
      <a href="http://localhost:80/oauth2/authorization/kakao?redirect_uri=http://localhost:8081/login/oauth2/code/kakao" class="btn"><img src="../../assets/images/kakaoLogin.png" width="260" height="60">
        </a>
      <a href="http://localhost:80/oauth2/authorization/google?redirect_uri=http://localhost:8081/login/oauth2/code/google" class="btn"><img src="../../assets/images/googleSignup.png" width="280">
      </a>
      <a href="http://localhost:80/oauth2/authorization/naver?redirect_uri=http://localhost:8081/login/oauth2/code/naver" class="btn"><img src="../../assets/images/naverLogin.png" width="270">
      </a>
    </div>
</template>

<script>
window.onload = function () {
  var getToken = document.location.href.split("/?token=");
  if (getToken[0] == "http://localhost:8081") {
    localStorage.setItem("getTk", getToken[1]);
    }
};

export default {};

// import { mapMutations, mapActions } from 'vuex'

// export default {
//   created () {
//     // 컴포넌트 렌더링이 되었을 때,

//     // 쿼리스트링으로부터 토큰을 획득
//     const token = this.$route.query.token
//     console.log('token', token)

//     // 토큰이 존재하는 경우, Vuex Store에 토큰을 저장한다.
//     if (token) {
//       this.setToken(token)
//       this.fetchUser()
//     }

//     // 토큰이 있던 없던, 루트 페이지로 이동한다.
//     this.$router.replace('/')
//   },
//   methods: {
//     ...mapActions(['fetchUser']),
//     ...mapMutations(['setToken'])
//   }
// }
</script>

<style scoped>
.col {
  float: left;
  width: 50%;
  margin: auto;
  padding: 0 50px;
  margin-top: 6px;
}
input,
.btn {
  width: 700px;
  padding: 12px;
  border: none;
  /* border-radius: 4px; */
  margin: 5px 0;
  /* opacity: 0.85; */
  display: inline-block;
  font-size: 17px;
  /* line-height: 20px; */
  text-decoration: none; /* remove underline from anchors */
}
.google {
  background-color: white;
  color: white;
}

.kakao {
  background-color: #fffc33;
  color: rgb(68, 58, 0);
}

.naver {
  background-color: #02ff24;
  color: rgb(255, 255, 255);
}
input:hover,
.btn:hover {
  opacity: 1;
}
</style>