import Vue from "vue";
import App from "./App.vue";
import router from "./router/router";
import store from "./store";
import '@fortawesome/fontawesome-free/js/all.js'

import "./assets/css/bootstrap.css";
import "./assets/css/bootstrap.min.css";
import "./assets/css/customcss.css";

Vue.config.productionTip = false;

new Vue({
  router,
  store,
  beforeCreate() {
    this.$store.dispatch("getUserInfo");
  },
  render: (h) => h(App),
}).$mount("#app");
