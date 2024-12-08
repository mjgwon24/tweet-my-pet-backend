package tweet_my_pet.tweet_my_pet_backend.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import tweet_my_pet.tweet_my_pet_backend.entity.Pet;
import java.util.Optional;
import tweet_my_pet.tweet_my_pet_backend.entity.PetSizeType;

@Repository
public interface PetRepository extends JpaRepository<Pet, Long> {

    @Query("SELECT p FROM Pet p WHERE p.petSize = :petSize")
    Optional<Pet> findPetBySize(@Param("petSize") PetSizeType petSize);

    @Query(value = "SELECT * FROM tweet_my_pet.pet WHERE pet_size = CAST(:petSize AS pet_size_type)", nativeQuery = true)
    Optional<Pet> findPetBySizeNative(@Param("petSize") String petSize);

    @Query("SELECT MAX(p.petId) FROM Pet p")
    Long findMaxPetId();
}
