package tweet_my_pet.tweet_my_pet_backend.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.Hibernate;

import java.util.Objects;

@Getter
@Setter
@Embeddable
public class StoreCategoryMappingId implements java.io.Serializable {
    private static final long serialVersionUID = -7479129836050331227L;
    @Column(name = "company_category_id", nullable = false)
    private Integer companyCategoryId;

    @Column(name = "company_id", nullable = false)
    private Long companyId;

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || Hibernate.getClass(this) != Hibernate.getClass(o)) return false;
        StoreCategoryMappingId entity = (StoreCategoryMappingId) o;
        return Objects.equals(this.companyId, entity.companyId) &&
                Objects.equals(this.companyCategoryId, entity.companyCategoryId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(companyId, companyCategoryId);
    }

}