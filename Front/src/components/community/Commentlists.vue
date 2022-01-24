<template>
  <div>
    <div class="con reply">
      <div class="form-group">
        <div class="form-group">
          <div class="input-group mb-3">
            <input type="text" class="form-control" />
            <button class="btn btn-primary" type="button" id="button-addon2">
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
          <tbody>
            <tr>
              <td>빙봉</td>
              <td class="commentd">아따 css 어렵구만</td>
            </tr>
            <tr>
              <td>내용1</td>
              <td class="commentd">내용2</td>
            </tr>
            <tr>
              <td>내용1</td>
              <td class="commentd">내용2</td>
            </tr>
            <tr>
              <td>내용1</td>
              <td class="commentd">내용2</td>
            </tr>
            <tr>
              <td>내용1</td>
              <td class="commentd">내용2</td>
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

export default {
  data() {
    return {
      comments: [],
      props: {
        postcomment:{
          
        }
      }
    };
  },
  computed: {
    ...mapState(["isLogin"]),
  },
  created() {
    console.log("하이");
    console.log(this.postcomment);
    let token = localStorage.getItem("getToken");
    http
      .get("/post/" + this.postId + "/comments", {
        headers: { Authorization: `Bearer ${token}` },
      })
      .then((res) => {
        this.comments = res.data;
      })
      .catch((err) => {
        console.log(err);
      });
  },
};
</script>
<style>
</style>