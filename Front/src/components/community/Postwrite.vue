<template>
  <div class="contents">
    <div class="form-group">
      <div class="card">
        <div class="card-body">
          <input
            class="pu-form-control"
            id="exampleTextarea"
            rows="1"
            v-model="title"
            placeholder="제목을 입력해주세요."
          />
          <br />
          <select class="form-select" v-model="cate" >
            <option value="QnA">질문</option>
            <option value="free">자유</option>
            <option value="share">나눔거래</option>
          </select>

          <br />

          <input
            class="form-control"
            v-bind="fileList"
            id="input_img"
            type="file"
            accept="image/*"
            multiple
            @change="fileChange"
          />

          <br />
          <div class="form-group">
            <textarea
              class="pu-form-control"
              id="exampleTextarea"
              rows="10"
              v-model="content"
              placeholder="내용을 입력해주세요."
            ></textarea>
          </div>
          <br /><br />
          <div class="pubutton">
            <button
              type="button"
              class="btn btn-outline-primary"
              @click="addPost"
            >
              저장하기
            </button>
          </div>
        </div>
      </div>
      <br />
    </div>
  </div>
</template>
<script>
import http from "@/util/http-common";

export default {
  name: "postwrite",
  data: () => ({
    cate: "",
    title: "",
    content: "",
    userId: "",
    fileList: [],
    fileUrl: "",
  }),
  created() {
    this.userId = localStorage.getItem("getId");
  },
  methods: {
    async fileChange() {
      let file = document.getElementById("input_img");
      var form = new FormData();
      form.append("image", file.files[0]);
      try {
        const res = await http.post(
          "https://api.imgbb.com/1/upload?key=076f41cee131349132a08f6320271a31",
          form
        );
        const { data } = res;
        this.fileUrl = data.data.url;
      } catch (error) {
        console.log(error);
        this.fileUrl = "";
      }
    },

    addPost() {
      let token = localStorage.getItem("getToken");
      let userId = localStorage.getItem("getId");
      let data = {
        title: this.title,
        category: this.cate,
        content: this.content,
        fileUrl: this.fileUrl,
      };
      http
        .post(
          "user/" + userId + "/post",
          data,
          // {headers: { Authorization: `Bearer ${token}`,'Content-Type': 'multipart/form-data'}
          { headers: { Authorization: `Bearer ${token}`, userId: userId } }
        ) //게시글을 추가
        .then((response) => {
          console.log(response);

          alert("저장 성공");
          // alert(localStorage.getItem('fileUrl'))
          localStorage.removeItem("fileUrl");
          this.$router.go(-1);
          // this.$router.go(this.$router.go(-1), alert('저장완료'))
        })
        .catch((error) => {
          console.log(error);
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
  min-width: 800px;
  position: relative;
  float: center;
}

.form-control-plaintext {
  display: block;
  width: 100%;
  padding: 0.375rem 0;
  padding-bottom: 20px;
  margin-bottom: 0;
  line-height: 1.5;
  color: #888;
  background-color: transparent;
  border: solid transparent;
  border-width: 1px 0;
}
input {
  width: 100%;
}
</style>
