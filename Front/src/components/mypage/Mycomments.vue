<template>
  <div class="contents">
    <div>
      내가 쓴 댓글 {{ comments.length }}

      <table class="table table-hover">
        <thead>
          <tr>
            <th scope="col" style="width: 60%">내용</th>
            <th scope="col">작성자</th>
            <th scope="col">좋아요</th>
            <th scope="col">삭제</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="(comment, idx) in comments" :key="idx">
            <th scope="row" class="titletd">
              &nbsp;&nbsp;{{ comment.content }}
            </th>
            <td>{{ comment.writer }}</td>
            <td>{{ comment.like }}</td>
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
      comments: [],
    };
  },
  created() {
    let userId = localStorage.getItem("getId");
    http
      .get("/user/" + userId + "/comments") 
      .then((res) => {
        this.comments = res.data;
        console.log(this.comments);
      })
      .catch((err) => {
        console.log(err);
      });
  },
  methods: {
    //12/25 현재 postId랑 commentId가져오는 법 모색중
    deletecomment() {
      let postId = this.comments.postId;
      let commentId = this.comments.commentId;
      http
        .delete("/post/" + postId + "/comment/" + commentId) 
        .then((res) => {
          this.posts = res.data;
          console.log(res);
        })
        .catch((err) => {
          console.log(err);
        });
    },
  },
};
</script>
<style>
</style>