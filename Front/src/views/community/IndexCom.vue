<template>
  <div class="contents">
    <div style="text-align: left; margin: 20px 0px 30px 15px">
      <router-link :to="{ name: 'postwrite' }">
        <button class="btn btn-dark" style="float: right" v-if="isLogin">
          글 쓰기
        </button>
      </router-link>
      <a :href="$router.resolve({ name: 'community' }).href">
        <button type="button" class="btn btn-warning" style="margin-right: 5px">
          전체
        </button>
      </a>
      <button
        type="button"
        class="btn btn-primary"
        style="margin-right: 5px"
        @click="clickFree"
      >
        자유
      </button>
      <button
        type="button"
        class="btn btn-secondary"
        style="margin-right: 5px"
        @click="clickTrade"
      >
        나눔/거래
      </button>
      <button
        type="button"
        class="btn btn-success"
        style="margin-right: 5px"
        @click="clickQuestion"
      >
        질문
      </button>
    </div>
    <table class="table table-hover">
      <thead>
        <tr>
          <th scope="col" style="width: 55%">제목</th>
          <th scope="col">작성자</th>
          <th scope="col">좋아요</th>
          <th scope="col">조회수</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="(post, i) in paginatedData" :key="i">
          <th scope="row" class="titletd" @click="clicketest(post), moveDetail">
            <a>
              <div>
                <router-link
                  :to="{
                    name: 'postdetail',
                    params: { userId: userId, postId: post.id },
                  }"
                  style="color:#434d47; text-decoration:none;"
                >
                  {{ post.title }}
                </router-link>
              </div>
            </a>
          </th>
          <td>{{ post.writer }}</td>
          <td>{{ post.like }}</td>
          <td>{{ post.hits }}</td>
        </tr>
      </tbody>
    </table>
    <div class="btn-cover">
      <button
        :disabled="pageNum === 0"
        @click="prevPage"
        class="btn btn-outline-primary"
      >
        이전
      </button>
      &nbsp;
      <span class="page-count">{{ pageNum + 1 }} / {{ pageCount }} 페이지</span>
      &nbsp;
      <button
        :disabled="pageNum >= pageCount - 1"
        @click="nextPage"
        class="btn btn-outline-primary"
      >
        다음
      </button>
    </div>
  </div>
</template>

<script>
import http from "@/util/http-common";
import { mapState } from "vuex";

export default {
  name: "community",

  data() {
    return {
      posts: [],
      userId: "",
      pageNum: 0,
    };
  },
  computed: {
    ...mapState(["isLogin"]),
    ...mapState(["userInfo"]),
    pageCount() {
      let listLeng = this.posts.length,
        listSize = this.pageSize,
        page = Math.floor(listLeng / listSize);
      if (listLeng % listSize > 0) page += 1;

      return page;
    },
    paginatedData() {
      const start = this.pageNum * this.pageSize,
        end = start + this.pageSize;
      return this.posts.slice(start, end);
    },
  },
  created() {
    this.userId = localStorage.getItem("getId");
    let token = localStorage.getItem("getToken");
    http
      .get("/posts/", { headers: { Authorization: `Bearer ${token}` } })
      .then((res) => {
        this.posts = res.data;
        console.log(this.posts);
      })
      .catch((err) => {
        console.log(err);
      })
      .then(() => {});
  },
  props: {
    listArray: {
      type: Array,
      required: true,
    },
    pageSize: {
      type: Number,
      required: false,
      default: 11,
    },
  },
  methods: {
    clicketest(value) {
      let PostId = value.id;
      let token = localStorage.getItem("getToken");
      let hits = value.hits + 1;
      http
        .put(
          "/post/" + PostId,
          {
            title: value.title,
            category: value.category,
            content: value.content,
            hits: hits,
            fileUrl: value.fileUrl,
          },
          { headers: { Authorization: `Bearer ${token}` } }
        )
        .then((response) => {
          this.posts = response.data;
        })
        .catch((err) => {
          console.log(err);
        });
    },
    nextPage() {
      this.pageNum += 1;
    },
    prevPage() {
      this.pageNum -= 1;
    },
    clickFree() {
      let postCategory = "free";
      let token = localStorage.getItem("getToken");

      http
        .get("/posts/category/" + postCategory, {
          headers: { Authorization: `Bearer ${token}` },
        })
        .then((response) => {
          this.posts = response.data;
        })
        .catch((err) => {
          console.log(err);
        });
    },

    clickQuestion() {
      let postCategory = "QnA";
      let token = localStorage.getItem("getToken");

      http
        .get("/posts/category/" + postCategory, {
          headers: { Authorization: `Bearer ${token}` },
        })
        .then((response) => {
          this.posts = response.data;
          console.log(this.posts);
        })
        .catch((err) => {
          console.log(err);
        });
    },
    clickTrade() {
      let postCategory = "share";
      let token = localStorage.getItem("getToken");

      http
        .get("/posts/category/" + postCategory, {
          headers: { Authorization: `Bearer ${token}` },
        })
        .then((response) => {
          this.posts = response.data;
        })
        .catch((err) => {
          console.log(err);
        });
    },
    moveDetail() {},
  },
};
</script>

<style scoped></style>
