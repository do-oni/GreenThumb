<template>
  <div>
    <a
      class="
        list-group-item list-group-item-action
        flex-column
        align-items-start
      "
    >
      <ol>
        <li>
          <img :src="myplant.imageUrl" />
          <div class="form-group">
            <input
              class="form-control"
              type="file"
              accept="image/*"
              id="input_img"
              v-bind="fileList"
              @change="fileChange"
              multiple
            />
          </div>
          <p class="mb-3"></p>
        </li>

        <li>
          한달에
          <input
            type="text"
            style="width: 50px; text-align: center"
            v-model.trim="myplant.water"
          />번 물을 주세요!
        </li>
        <li>
          저는<input
            type="text"
            style="width: 50px; text-align: center"
            v-model.trim="myplant.temp"
          />도를 가장 좋아합니다!
        </li>
        <small
          ><input
            type="text"
            style="width: 130px; text-align: center"
            v-model.trim="myplant.nickName"
          />의 가족은<input
            type="text"
            style="width: 130px; text-align: center"
            v-model.trim="myplant.name"
          />라고 합니다.</small
        ><br />
      </ol>
      <div>
        <button class="btn btn-primary" @click="postUpdate">완료</button>
        <button class="btn btn-primary" @click="boardCancelClick">취소</button>
      </div>
    </a>
  </div>
</template>
<script>
import { mapState } from "vuex";
import http from "@/util/http-common";

export default {
  name: "editplant",
  data() {
    return {
      myplant: [],
      fileList: [],
    };
  },
  props: {
    plantId: {},
    userId: {},
  },
  computed: {
    ...mapState(["userInfo"]),
  },
  created() {
    let token = localStorage.getItem("getToken");
    http
      .get("plant/" + this.$route.params.plantId, {
        headers: { Authorization: `Bearer ${token}` },
      })
      .then((res) => {
        this.myplant = res.data;
        console.log(res.data);
      })
      .catch((err) => {
        console.log(err);
      })
      .then(() => {});
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
        this.myplant.imageUrl = data.data.url;
      } catch (error) {
        console.log(error);
        this.myplant.imageUrl = "";
      }
    },
    postUpdate() {
      let userId = localStorage.getItem("getId");
      let token = localStorage.getItem("getToken");
      // if(fileUrl == null){
      //     fileUrl = this.myplant.imageUrl
      // }
      var data = {
        userId: userId,
        name: this.myplant.name,
        nickName: this.myplant.nickName,
        water: this.myplant.water,
        temp: this.myplant.temp,
        imageUrl: this.myplant.imageUrl,
      };
      http
        .put(
          "user/" +
            // this.$route.params.userId +
            userId+
            "/plant/" +
            this.$route.params.plantId,
          data,
          {
            headers: { Authorization: `Bearer ${token}` },
          }
        )
        .then((res) => {
          console.log(res.data);
        })
        .catch((err) => {
          console.log(err);
        })
        .then(() => {
          // this.$router.go(-1, alert("수정완료"));
          alert("수정완료")
          // this.$router.go({name:'IndexMain'});
          localStorage.removeItem("fileUrl");
          this.$router.push({name:'IndexMain'});
        });
    },
    boardCancelClick() {
      this.$router.go(-1);
    },
  },
};
</script>
    
<style>
ol,
ul {
  list-style: none;
  margin: 0px;
  padding: 0px;
}
img {
  width: 550px;
  border-radius: 15px;
}
</style>