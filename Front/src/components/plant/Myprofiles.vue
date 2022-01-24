<template>
  <div>
    <div class="list-group">
      <span
        class="
          list-group-item list-group-item-action
          flex-column
          align-items-start
          active
        "
      >
        <div class="d-flex w-100 justify-content-between">
          <h4 class="mb-1">{{ User.nickName }}</h4>
          <ul v-show="checkSelf">
            <li v-if="canFollow">
              <button  class="btn btn-light" @click="followerupdate">
                팔로우 하기
              </button>
            </li>
            <li v-else>
              <button  class="btn btn-light" @click="followerdelete">
                팔로우 취소
              </button>
            </li>
          </ul>
        </div>
      </span>

      <span
        class="
          list-group-item list-group-item-action
          flex-column
          align-items-start
        "
      >
        <div class="d-flex w-100 justify-content-between">
          <h6 class="mb-1"></h6>
          <ul>
            <li>
              <button @click="showModal = true" class="text-muted">
                팔로우수: {{ User.followeeCount }}
              </button>
              &nbsp;&nbsp;
              <button @click="showfollowing=true" class="text-muted">
                팔로잉 수: {{ User.followerCount }}
              </button>
            </li>
          </ul>
        </div>
        <p class="mb-1" style="text-align: left">
          {{ User.profile }}
        </p>
      </span>
     
    </div>
     <!-- 팔로우 모달창 -->
    <div >
      <modal :feedowner="User.userId" v-if="showModal" @close="showModal = false">
        <h4 slot="follower">팔로워 리스트</h4>
      </modal>
            <following :feedowner="User.userId" v-if="showfollowing" @close="showfollowing = false">
        <h4 slot="follower">팔로잉 리스트</h4>
      </following>
    </div>

  </div>
</template>
<script>
import { mapState } from "vuex";
import http from "@/util/http-common";
import modal from "../../components/modal/modal.vue";
import following from "../../components/modal/follower.vue"

export default {
  name: "Myprofile",
  components: {
    modal,
    following,
  },
  data() {
    return {
      myplants: [],
      User: [],
      canFollow: true,
      checkSelf: false,
      showModal:false,
      showfollowing:false
      
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
    let id = localStorage.getItem("getId");
    let token = localStorage.getItem("getToken");
    http
      .get("user/" + this.$route.params.userId + "/feed", {
        headers: { Authorization: `Bearer ${token}` },
      })
      .then((response) => {
        this.User = response.data;
        console.log(this.User)
      })
      .catch((err) => {
        console.log(err);
      })
      .then(() => {});

    if (id === this.$route.params.userId) {
      this.checkSelf = false;
    } else {
      this.checkSelf = true;
    }
  },
  methods: {
    followerupdate() {
      let token = localStorage.getItem("getToken");
      http
        .post(
          "user/" +
            this.$store.state.userInfo.userId +
            "/followee/" +
            this.$route.params.userId +
            "/follow",
          {
            headers: { Authorization: `Bearer ${token}` },
          }
        )
        .then((response) => {
          console.log(response);
        })
        .catch((err) => {
          console.log(err);
        })
        .then(() => {
          this.canFollow =!this.canFollow
          // this.$router.go(this.$router.currentRoute);
        });
    },
    followerdelete() {
      let token = localStorage.getItem("getToken");
      http
        .delete(
          "user/" +
            this.$store.state.userInfo.userId +
            "/followee/" +
            this.$route.params.userId +
            "/follow",
          {
            headers: { Authorization: `Bearer ${token}` },
          }
        )
        .then((response) => {
          console.log(response);
        })
        .catch((err) => {
          console.log(err);
        })
        .then(() => {
          this.$router.go(this.$router.currentRoute);
        });
    },
  },
};
</script>
<style>
li {
  list-style: none;
}
</style>