<template>
  <div class="contents">
    <div>
      내가 쓴 글 {{ posts.length }}

      <table class="table table-hover">
        <thead>
          <tr>
            <th scope="col" style="width: 60%">제목</th>
            <th scope="col">작성자</th>
            <th scope="col">좋아요</th>
            <th scope="col">조회수</th>
            <th scope="col">삭제</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="(post, idx) in posts" :key="idx">
            <th scope="row" class="titletd">&nbsp;&nbsp;{{ post.title }}</th>
            <td>{{ post.writer }}</td>
            <td>{{ post.like }}</td>
            <td>{{ post.hits }}</td>
            <td>
              <button
                type="button"
                class="btn btn-warning"
                @click="deletecomment"
              >
                삭제하기
              </button>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>
<script>
import http from "@/util/http-common";

export default {
  data() {
    return {
      posts: [],
      userID: "",
    };
  },
  created() {
    this.userID = localStorage.getItem("getId");
    http
      .get("/posts/user/" + this.userID) //게시글 불러옴.
      .then((res) => {
        this.posts = res.data;
        console.log(res);
      })
      .catch((err) => {
        console.log(err);
      });
  },
};
</script>
<style>
</style>