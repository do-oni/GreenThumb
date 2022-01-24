<template>
  <div class="contents">
    <div class="card">
      <div class="card-body">
        <h4 class="card-title">{{ posts.title }}</h4>
        <br />
        <h6 class="card-subtitle mb-2 text-muted">{{ posts.writer }}</h6>
        <div>
          <span style="float: right"
            >좋아요 {{ posts.like }} 조회수 {{ posts.hits }}</span
          >
        </div>
        <br /><br />
        <div>
          <img class="imgSizeA" :src="posts.fileUrl" />
        </div>
        <br />
        <div>
          <p class="card-text">{{ posts.content }}</p>
        </div>

        <div class="heart" @click="clickLike">
          <a  style="font-size: xx-large; color: green">❤</a>
          <!-- <a
            v-show="yeslike == false"
            style="font-size: xx-large; color: lightgrey"
            >❤</a
          > -->
          <br />
          <br />
        </div>
        <div class="pdbutton" v-if="chekcWrite==true">
          <!-- <router-link :to="{ name: 'postupdate', params: { postId: postId } }"> -->
            <button
              type="button"
              class="btn btn-outline-primary"
              @click="clickEdit"
            >
              수정하기
            </button>
          <!-- </router-link> -->
          &nbsp;
          <button type="button" class="btn btn-outline-primary">
            삭제하기
          </button>
        </div>
      </div>
    </div>
    <!-- <Commentlist :postcomment="posts.id"/> -->
    <div class="con reply">
      <div class="form-group">
        <div class="form-group">
          <div class="input-group mb-3">
            <input type="text" class="form-control" v-model="writecomment" />
            <button
              class="btn btn-primary"
              type="button"
              @click="createComment"
            >
              댓글 등록
            </button>
          </div>
        </div>
      </div>
      <section class="reply-list table-common">
        <table class="commenttable" border="1">
          <colgroup>
            <col width="100px" />
          </colgroup>
          <tbody v-for="(comment, id) in comments" :key="id">
            <tr>
              <td style="float: left">{{ comment.writer }}</td>
              <td class="commentd">{{ comment.content }}</td>
            </tr>
          </tbody>
        </table>
      </section>
    </div>
  </div>
</template>
<script>
import http from "@/util/http-common";
import { mapState } from "vuex";
// import Commentlist from "../community/Commentlists.vue";

export default {
  name: "postdetail",
  components: {
    // Commentlist,
  },
  data() {
    return {
      posts: [],
      yeslike: false,
      comments: [],
      writecomment: "",
      chekcWrite: false,
    };
  },
  props: {
    postId: {},
    userId: {},
  },
  computed: {
    ...mapState(["isLogin"]),
    ...mapState(["userInfo"]),
  },
  // watch: {
  //   $route(to, from) {
  //     if (to.path != from.path) {
  //       this.$router.go(this.$router.currentRoute);
  //     }
  //   },
  // },
  created() {
    
    let token = localStorage.getItem("getToken");
    http
      .get("/post/" + this.$route.params.postId, {
        headers: { Authorization: `Bearer ${token}` },
      })
      .then((res) => {
        this.posts = res.data;
        this.writerId = res.data.writerId;
        this.logId = localStorage.getItem("getId");

        if (this.writerId == this.logId) {
          this.chekcWrite = true;
        }
      })
      .catch((err) => {
        console.log(err);
      });
    http
      .get("post/" + this.postId + "/comments", {
        headers: { Authorization: `Bearer ${token}` },
      })
      .then((response) => {
        this.comments = response.data;
        console.log(response.data);
      })
      .catch((err) => {
        console.log(err);
      });
  },
  methods: {
    clickEdit() {
      this.$router.push({ name: "postupdate", params: { postId:  this.postId} });
    },
    clickLike() {
      let token = localStorage.getItem("getToken");
      let id = localStorage.getItem("getId");
      http
        .post("/post/" + this.postId + "/user/" + id + "/like", {
          headers: { Authorization: `Bearer ${token}` },
        })
        .then((res) => {
          // console.log(res);
          this.like = res.data;
          this.yeslike = !this.yeslike;
          alert(this.like);
          // this.$router.go(this.$router.currentRoute);
        })
        .catch((err) => {
          console.log(err);
        });
    },
    createComment() {
      let token = localStorage.getItem("getToken");
      var data = {
        userId: localStorage.getItem("getId"),
        content: this.writecomment,
      };
      http
        .post("post/" + this.postId + "/comment", data, {
          headers: { Authorization: `Bearer ${token}` },
        })
        .then((res) => {
          console.log(res.data);
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
<style scoped>
.card-body {
  -ms-flex: 1 1 auto;
  flex: 1 1 auto;
  padding: 5%;
  min-height: 400px;
  position: relative;
  float: center;
}
.heart:hover {
  cursor: pointer;
}
.imgSizeA {
  width: 180px;
  height: 180px;
  vertical-align: center;
  padding: 10px 10px 10px 10px;
  border-radius: 15px;
}
</style>
