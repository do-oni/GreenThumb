<template>
  <div>
    <form>
      <fieldset style="float: left">
        <legend>💊식물병원이에요💊</legend>

        <div class="form-group">
          <label for="formFile" class="form-label mt-4"
            >식물을 진단합니다🩺</label
          >
          <input
            class="form-control"
            type="file"
            id="input_img"
            accept="image/*"
            v-bind="fileList"
            @change="fileChange"
          />
          <div>
            <img class="imgSizeA" :src="this.file" />
          </div>
          <hr />
          <button type="button" class="btn btn-primary" @click="uploadFile">
            진찰하기
          </button>

          <div class="resultform">
            <ul>
              <div></div>
              <hr />

              <div>
                <p>당신의 식물은</p>
                <h3>{{ Hospital.diseaseName }}</h3>
                <p>을 앓고 있습니다.</p>
                <h5>병에 대한 해결책</h5>
                <p>{{ Hospital.content }}</p>
              </div>
            </ul>
          </div>
        </div>
      </fieldset>
    </form>
  </div>
</template>


<script>
import http from "@/util/http-common";

export default {
  name: "Hospital",
  data() {
    return {
      fileList: [],
      Hospital: [],
      file: "",
    };
  },

  methods: {
    //식물 이미지 링크 받아오는 api
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
        this.file = data.data.url;
      } catch (error) {
        console.log(error);
        this.file = "";
      }
    },
    //식물 이미지 보내는 rest api
    uploadFile() {
      // console.log("uploadFile")
      // console.log(this.file)
      http
        .post("http://localhost:80/plant-hospital", { imageUrl: this.file })
        .then((res) => {
          this.Hospital = res.data;
          console.log(res.data);
        })
        .catch((err) => {
          console.log(err);
        })
        .then(() => {});
    },
    // async getAnswer() {
    //   const filesurls = this.file;
    //   //(2)vuex의 스토어에 저장해둔 dataId를 가져온다.
    //   const { data } = await checkId(dataId);
    //   //(3)async await로 checkId API 호출.
    //   if (data.status == "done") {
    //     //(4)해당 status 값이 done이면 아래 코드 실행
    //     clearInterval(this.loading);
    //     //(5)clearInterval()에 setInterval에서 반환한 인스턴스를 넣는다.
    //     this.status = data.status;
    //   }
    // },
  },
};
</script>
<style scoped>
.imgSizeA {
  width: 180px;
  height: 180px;
  vertical-align: center;
  padding: 10px 10px 10px 10px;
  border-radius: 15px;
}
</style>
