package com.ssh.greenthumb.api.dao.plant;

import com.ssh.greenthumb.api.domain.plant.Plant;
import com.ssh.greenthumb.api.domain.user.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface PlantRepository extends JpaRepository<Plant, Long> {

    List<Plant> findAllByUser(User user);

    List<Plant> findAllByName(String name);

}